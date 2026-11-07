/**
 * This file is part of Darling.
 *
 * Copyright (C) 2021 Darling developers
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Darling is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Darling.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE 1
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <sys/uio.h>

#include <darlingserver/logging.hpp>
#include <darlingserver/duct-tape.h>
#include <darlingserver/config.hpp>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <darlingserver/kqchan.hpp>
#include <utility> // x86Sim

static DarlingServer::Log callLog("calls");

DarlingServer::Log DarlingServer::Call::rpcReplyLog("replies");


// x86Sim (Speed 36): opt-in RPC counters for the mach_msg fast-path study. On while the file
// /home/bobby/scratch/x86sim/ds-rpcstats.on exists (checked once a second); every second with traffic, one line of
// per-call-number counts and mach_msg shapes is appended to /home/bobby/scratch/x86sim/ds-rpcstats.log.
#include <atomic>
#include <ctime>
#include <unistd.h>
#include <cstdio>
extern "C" int x86sim_rpcstats_on;
int x86sim_rpcstats_on = 0;
static std::atomic<uint64_t> x86sim_calls[512];
// shapes: 0 simple no-local, 1 simple + local send-once (request), 2 simple + other local, 3 complex, 4 voucher; +5 when combined with a receive
static std::atomic<uint64_t> x86sim_shapes[10];
extern "C" void x86sim_rpcstat_msg(unsigned int bits, int rcv) {
	int k = (bits & 0x80000000u) ? 3 : ((bits >> 16) & 0x1f) ? 4 : ((bits >> 8) & 0x1f) == 0 ? 0 :
		((bits >> 8) & 0x1f) == 21 /* MAKE_SEND_ONCE */ ? 1 : 2;
	x86sim_shapes[k + (rcv ? 5 : 0)]++;
}
extern "C" void x86sim_rpcstat_slot(unsigned slot) {
	if (x86sim_rpcstats_on && slot < 512) x86sim_calls[slot]++;
}
static void x86sim_rpcstats_tick(unsigned number) {
	static std::atomic<int64_t> last{0};
	timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	int64_t sec = ts.tv_sec, l = last.load();
	if (sec != l && last.compare_exchange_strong(l, sec)) {
		bool was = x86sim_rpcstats_on;
		x86sim_rpcstats_on = access("/home/bobby/scratch/x86sim/ds-rpcstats.on", F_OK) == 0;
		if (was) {
			FILE* f = fopen("/home/bobby/scratch/x86sim/ds-rpcstats.log", "a");
			if (f) {
				fprintf(f, "t=%lld calls", (long long)sec);
				for (int i = 0; i < 512; i++) { uint64_t c = x86sim_calls[i].exchange(0); if (c) fprintf(f, " %d:%llu", i, (unsigned long long)c); }
				fprintf(f, " | shapes");
				for (int i = 0; i < 10; i++) fprintf(f, " %llu", (unsigned long long)x86sim_shapes[i].exchange(0));
				fprintf(f, "\n");
				fclose(f);
			}
		}
	}
	if (x86sim_rpcstats_on && number < 512) x86sim_calls[number]++;
}
std::shared_ptr<DarlingServer::Call> DarlingServer::Call::callFromMessage(Message&& requestMessage) {
	if (requestMessage.data().size() < sizeof(dserver_rpc_callhdr_t)) {
		throw std::invalid_argument("Message buffer was too small for call header");
	}

	dserver_rpc_callhdr_t* header = reinterpret_cast<dserver_rpc_callhdr_t*>(requestMessage.data().data());
	std::shared_ptr<Call> result = nullptr;
	x86sim_rpcstats_tick(header->number);
	std::shared_ptr<Process> process = nullptr;
	std::shared_ptr<Thread> thread = nullptr;

	// first, make sure we know this call number
	switch (header->number) {
		case dserver_callnum_s2c:
		case dserver_callnum_push_reply:
		DSERVER_VALID_CALLNUM_CASES
			break;

		default:
			throw std::invalid_argument("Invalid call number");
	}

	if ((header->number & DSERVER_CALL_UNMANAGED_FLAG) == 0) {
		// now let's lookup (and possibly create) the process and thread making this call
		process = processRegistry().registerIfAbsent(header->pid, [&]() {
			std::shared_ptr<Process> tmp = nullptr;

			int lifetimePipe = -1;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				if (checkinCall->body.lifetime_listener_pipe != -1) {
					lifetimePipe = requestMessage.extractDescriptorAtIndex(checkinCall->body.lifetime_listener_pipe);
					checkinCall->body.lifetime_listener_pipe = -1;
				}
			}

			try {
				tmp = std::make_shared<Process>(requestMessage.pid(), header->pid, static_cast<Process::Architecture>(header->architecture), lifetimePipe);
			} catch (std::system_error e) {
				return tmp;
			}

			Server::sharedInstance().monitorProcess(tmp);
			return tmp;
		});

		if (!process) {
			callLog.error() << "Received call from non-existent process?" << callLog.endLog;

			// ignore this call
			// TODO: instead of ignoring it, we should return a generic reply indicating `-ESRCH` or something like that.
			return nullptr;
		}

		thread = threadRegistry().registerIfAbsent(header->tid, [&]() {
			std::shared_ptr<Thread> tmp = nullptr;

			void* stackHint = nullptr;

			if (header->number == dserver_callnum_checkin) {
				auto checkinCall = reinterpret_cast<dserver_rpc_call_checkin_t*>(header);
				stackHint = reinterpret_cast<void*>(checkinCall->body.stack_hint);
			}

			try {
				tmp = std::make_shared<Thread>(process, header->tid, stackHint);
			} catch (std::system_error e) {
				return tmp;
			}

			tmp->setAddress(requestMessage.address());
			tmp->registerWithProcess();
			return tmp;
		});

		if (!thread) {
			callLog.error() << "Received call from non-existent thread?" << callLog.endLog;

			// ignore this call
			// TODO: instead of ignoring it, we should return a generic reply indicating `-ESRCH` or something like that.
			return nullptr;
		}

		thread->setAddress(requestMessage.address());

		if (process->id() != requestMessage.pid()) {
			throw std::runtime_error("System-reported message PID != darlingserver-recorded PID");
		}
	}

	auto pidString = (process) ? (std::to_string(process->id()) + " (" + std::to_string(process->nsid()) + ")") : (std::to_string(header->pid) + " (-1)");
	auto tidString = (thread) ? (std::to_string(thread->id()) + " (" + std::to_string(thread->nsid()) + ")") : (std::to_string(header->tid) + " (-1)");
	callLog.debug() << "Received call #" << header->number << " (" << dserver_callnum_to_string(header->number) << ") from PID " << pidString << ", TID " << tidString << callLog.endLog;

	if (header->number == dserver_callnum_s2c) {
		// this is an S2C reply

		// x86Sim (willi/darlingserver#10): taken under the lock (a released thread has none) and retained
		dtape_semaphore_t* replySemaphore;
		{
			std::unique_lock lock(thread->_rwlock);

			if (thread->_s2cAbandonedReplies > 0) {
				// x86Sim: the reply to an S2C call whose caller stopped waiting after sending it (Thread::_s2cPerform()).
				// Taken as the next call's reply, it was that call's "duplicate"; the next call's own reply was dropped,
				// and its caller got another call's answer (or none, and its thread hung in its S2C interrupt).
				thread->_s2cAbandonedReplies--;
				callLog.warning() << *thread << ": dropped the late reply of an abandoned S2C call" << callLog.endLog;
				return nullptr;
			}

			if (thread->_s2cReply) {
				// x86Sim: a client's second S2C reply is its protocol error: drop it instead of throwing out of the
				// main loop and taking every process down with darlingserver (as willi/darlingserver#7 contains it;
				// seen once Swift's cooperative pool made workqueue threads come and go much more often)
				callLog.error() << *thread << ": Received S2C reply but thread already had one pending; dropped it" << callLog.endLog;
				return nullptr;
			}

			thread->_s2cReply = std::move(requestMessage);
			replySemaphore = thread->_s2cReplySempahore;
			if (replySemaphore) {
				dtape_semaphore_retain(replySemaphore);
			}
		}

		if (replySemaphore) {
			dtape_semaphore_up(replySemaphore);
			dtape_semaphore_release(replySemaphore);
		}

		return nullptr;
	} else if (header->number == dserver_callnum_push_reply) {
		// this is a reply push
		// (used to send interrupted replies back to the server)

		auto pushReplyCall = reinterpret_cast<const dserver_rpc_call_push_reply_t*>(requestMessage.data().data());
		Message replyToSave(pushReplyCall->reply_size, 0);

		// extract the reply-push synchronization pipe
		// owned here so it is closed on every exit; the client is blocked on the read end and EOF releases it
		FD pipeDesc(requestMessage.extractDescriptorAtIndex(requestMessage.descriptors().size() - 1));
		char tmp = 1;

		if (!pipeDesc) {
			throw std::runtime_error("Failed to extract reply-push synchronization pipe");
		}

		if (!process->readMemory(pushReplyCall->reply, replyToSave.data().data(), pushReplyCall->reply_size)) {
			throw std::runtime_error("Failed to read client-pushed reply body");
		}

		replyToSave.replaceDescriptors(requestMessage.descriptors());
		requestMessage.replaceDescriptors({});

		replyToSave.setAddress(requestMessage.address());

		{
			std::unique_lock lock(thread->_rwlock);
			if (thread->_pendingCall && thread->_pendingCall->number() == Call::Number::InterruptEnter) {
				// this means the client got interrupted after we had already sent a reply for the interrupted call,
				// the client saw this unexpected reply while waiting for interrupt_enter to respond and sent it back to us,
				// and we received both calls (interrupt_enter and push_reply) at the same time
				thread->_pendingSavedReply = std::move(replyToSave);
			} else {
				if (thread->_interrupts.empty()) {
					throw std::runtime_error("Client tried to push reply outside of interrupt");
				}
				if (thread->_interrupts.top().savedReply) {
					throw std::runtime_error("Client-pushed reply overwriting existing saved reply");
				}
				thread->_interrupts.top().savedReply = std::move(replyToSave);
			}
		}

		callLog.debug() << *thread << ": Saved client-pushed reply (" << ((thread->_pendingSavedReply) ? "pending" : "normal") << ")" << callLog.endLog;

		// write a byte to the pipe so the caller can continue
		write(pipeDesc.fd(), &tmp, sizeof(tmp));

		return nullptr;
	}

	// finally, let's construct the call class

	#define CALL_CASE(_callName, _className) \
		case dserver_callnum_ ## _callName: { \
			if (requestMessage.data().size() < sizeof(dserver_rpc_call_ ## _callName ## _t)) { \
				throw std::invalid_argument("Message buffer was too small for dserver_call_" #_callName "_t"); \
			} \
			result = std::make_shared<_className>(thread, reinterpret_cast<dserver_rpc_call_ ## _callName ## _t*>(header), std::move(requestMessage)); \
		} break;

	switch (header->number) {
		DSERVER_CONSTRUCT_CASES

		default:
			throw std::invalid_argument("Invalid call number");
	}

	#undef CALL_CASE

	// x86Sim (willi/darlingserver#14): Thread::_s2cPerform() gives mldr's checkin and thread-exit checkout the S2C
	// signal (mldr's RPC hooks abort on an S2C call); libsystem's (fork child's checkin, exec's checkout) serve it inline.
	if (auto checkin = std::dynamic_pointer_cast<Checkin>(result)) {
		result->_madeByMldr = !checkin->_body.is_fork;
	} else if (auto checkout = std::dynamic_pointer_cast<Checkout>(result)) {
		result->_madeByMldr = checkout->_body.exec_listener_pipe < 0;
	}

	if (thread) {
		// x86Sim (willi/darlingserver#13): a call queued behind the pending one is scheduled when that one is done
		if (!thread->setPendingCall(result)) {
			callLog.debug() << *thread << ": Call queued behind the pending call" << callLog.endLog;
			return nullptr;
		}
		return result;
	} else {
		Thread::kernelAsync([result]() {
			result->processCall();
		});
		return nullptr;
	}
};

DarlingServer::Call::Call(std::shared_ptr<Thread> thread, Address replyAddress, dserver_rpc_callhdr_t* callHeader):
	_thread(thread),
	_replyAddress(replyAddress),
	_header(*callHeader)
	{};

DarlingServer::Call::~Call() {};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Call::thread() const {
	return _thread.lock();
};

void DarlingServer::Call::sendBasicReply(int resultCode) {
	throw std::runtime_error("This call cannot send a basic reply");
};

void DarlingServer::Call::sendBSDReply(int resultCode, uint32_t returnValue) {
	throw std::runtime_error("This call cannot send a BSD reply");
};

bool DarlingServer::Call::isXNUTrap() const {
	return false;
};

bool DarlingServer::Call::isBSDTrap() const {
	return false;
};

void DarlingServer::Call::sendReply(Message&& reply) {
	Server::sharedInstance().sendMessage(std::move(reply));
};

//
// call processing
//

/*
 *
 * A note about RPC wrappers:
 *
 * The auto-generated RPC wrappers provide both client-side wrappers as well as server-side wrappers.
 * The server-side wrappers automatically handle a few things like replies and descriptors.
 *
 * Replies:
 * The RPC wrappers provide a custom `_sendReply` method specific to each call class.
 * This method takes the result/status code as its first parameter followed by the return parameters
 * specified in the call interface. When a call is done processing, it simply calls `_sendReply` with the necessary
 * parameters and the RPC wrappers will take care of setting up the message and loading it onto the reply queue
 * for the server to send it out.
 *
 * Descriptors:
 * The RPC wrappers automatically handle ownership of descriptors, both incoming and outgoing.
 *
 * Incoming descriptors are extracted from the message and ownership is moved into the call instance.
 * The call processing code can use the descriptor however it likes while the call instance is still alive.
 * If it would like to move ownership out of the call instance, it can set the descriptor in the `_body` to `-1`.
 * Descriptors still left in the `_body` when the call instance is destroyed are automatically closed.
 *
 * Ownership of outgoing descriptors is passed into the reply message. In other words, when a descriptor
 * is given to `_sendReply`, the call instance loses ownership of that descriptor. If the call instance
 * would like to retain ownership, it should `dup()` the descriptor and pass the `dup()`ed descriptor to `_sendReply` instead.
 *
 */

void DarlingServer::Call::Checkin::processCall() {
	// the Call instance creation already took care of registering the process and thread.

	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the process needs to know when the checkin occurs, in case it has a pending replacement
			// and also to notify its parent about when the fork is complete
			process->notifyCheckin(static_cast<Process::Architecture>(_header.architecture));
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Checkout::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.exec_listener_pipe >= 0) {
				// this is actually an execve;
				// let's monitor the FD we got

				// make it non-blocking
				int flags = fcntl(_body.exec_listener_pipe, F_GETFL);
				if (flags < 0) {
					code = -errno;
				} else {
					flags |= O_NONBLOCK;
					if (fcntl(_body.exec_listener_pipe, F_SETFL, flags) < 0) {
						code = -errno;
					} else {
						// now monitor it
						auto fd = std::make_shared<FD>(_body.exec_listener_pipe);
						_body.exec_listener_pipe = -1; // the FD instance now owns the descriptor

						auto replacingWithDarlingProcess = _body.executing_macho;

						std::weak_ptr<Process> weakProcess = process;
						Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::HangUp, false, true, [fd, weakProcess, replacingWithDarlingProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
							Server::sharedInstance().removeMonitor(monitor);

							auto process = weakProcess.lock();

							if (!process) {
								// the process died...
								return;
							}

							char tmp;
							int result = read(fd->fd(), &tmp, sizeof(tmp));

							if (result < 0) {
								// we shouldn't even get EAGAIN
								throw std::system_error(errno, std::generic_category(), "Failed to read from exec listener pipe");
							}

							if (result == 0) {
								// the execve succeeded
								if (replacingWithDarlingProcess) {
									process->setPendingReplacement();
								} else {
									// the Darling process was replaced with a non-Darling process
									// treat it like death
									process->notifyDead();
								}
							} else {
								// the execve failed
								// do nothing in this case
							}
						}));
					}
				}
			} else {
				thread->notifyDead();

				// if this was the last thread in the process, it'll be automatically unregistered
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	// x86Sim (willi/darlingserver#10): the call is over. A dead thread with no active call is released when it returns
	// to the top of its microthread (doneWorking); with `_thread` reset below, the reply no longer deactivated it, and a
	// checked-out thread stayed for ever (its duct-taped thread still in task_threads(), its stack). Not the main thread:
	// mldr parks its Linux thread and the process lives on; it is released with the process (notifyProcessDead()).
	// `self` keeps the call (the thread's active call held the only reference) until the reply is sent.
	std::shared_ptr<Call> self;
	if (auto thread = _thread.lock(); thread && (self = thread->activeCall()).get() == this && thread->process() && thread->id() != thread->process()->id()) {
		thread->deactivateCall(self);
	}

	// clear the thread pointer so that the reply will be sent directly through the server
	// (otherwise, we would attempt to send it through the thread, which is now dead)
	_thread.reset();

	_sendReply(code);
};

void DarlingServer::Call::VchrootPath::processCall() {
	int code = 0;
	size_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (_body.buffer_size > 0) {
				auto tmpstr = process->vchrootPath().substr(0, _body.buffer_size - 1);
				auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

				fullLength = process->vchrootPath().length();

				if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
					// writeMemory returns a positive error code, but we want a negative one
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::TaskSelfTrap::processCall() {
	const auto taskSelfPort = dtape_task_self_trap();
	_sendReply(0, taskSelfPort);
};

// x86Sim: fileports (see dtape_fileport_makeport)
void DarlingServer::Call::FileportMakeport::processCall() {
	uint32_t name = 0;
	int code = dtape_fileport_makeport(_body.fd, &name);
	if (code == 0) {
		_body.fd = -1; // the fileport owns it now
	}
	_sendReply(code, name);
};

void DarlingServer::Call::FileportMakefd::processCall() {
	int fd = -1;
	int code = dtape_fileport_makefd(_body.port_name, &fd);
	_sendReply(code, fd); // the reply message closes our copy once sent
};

// x86Sim: see dtape_memfd_for_region
void DarlingServer::Call::X86SimMemfdForRegion::processCall() {
	int fd = -1;
	uint64_t offset = 0;
	uint32_t shared = 0;
	int code = dtape_memfd_for_region(_body.address, _body.size, &fd, &offset, &shared);
	_sendReply(code, fd, offset, shared); // the reply message closes our copy once sent
};

void DarlingServer::Call::HostSelfTrap::processCall() {
	const auto hostSelfPort = dtape_host_self_trap();
	_sendReply(0, hostSelfPort);
};

void DarlingServer::Call::ThreadSelfTrap::processCall() {
	const auto threadSelfPort = dtape_thread_self_trap();
	_sendReply(0, threadSelfPort);
};

void DarlingServer::Call::MachReplyPort::processCall() {
	const auto machReplyPort = dtape_mach_reply_port();
	_sendReply(0, machReplyPort);
};

void DarlingServer::Call::Kprintf::processCall() {
	static auto kprintfLog = Log("kprintf");
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			char* tmp = (char*)malloc(_body.string_length + 1);

			if (tmp) {
				if (process->readMemory(_body.string, tmp, _body.string_length, &code)) {
					size_t len = _body.string_length;

					// strip trailing whitespace
					while (len > 0 && isspace(tmp[len - 1])) {
						--len;
					}
					tmp[len] = '\0';

					kprintfLog.info() << tmp << kprintfLog.endLog;
				} else {
					// readMemory returns a positive error code, but we want a negative one
					code = -code;
				}

				free(tmp);
			} else {
				code = -ENOMEM;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StartedSuspended::processCall() {
	int code = 0;
	bool suspended = false;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			suspended = process->startSuspended();
			process->setStartSuspended(false);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, suspended);
};

void DarlingServer::Call::GetTracer::processCall() {
	int code = 0;
	int32_t tracer = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			if (auto tracerProcess = process->tracerProcess()) {
				tracer = tracerProcess->nsid();
			} else {
				// leave `tracer` as 0
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, tracer);
};

void DarlingServer::Call::Uidgid::processCall() {
	int code = 0;
	int uid = -1;
	int gid = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// HACK
			// we shouldn't need to access _dtapeTask; Process should provide a method for this (but it doesn't yet because i'm not sure how to make that API feel at-home in C++)
			dtape_task_uidgid(process->_dtapeTask, _body.new_uid, _body.new_gid, &uid, &gid);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, uid, gid);
};

void DarlingServer::Call::SetThreadHandles::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->setThreadHandles(_body.pthread_handle, _body.dispatch_qaddr);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Vchroot::processCall() {
	int code = 0;

	// TODO: wrap all `processCall` calls in try-catch like this
	try {
		if (auto thread = _thread.lock()) {
			if (auto process = thread->process()) {
				process->setVchrootDirectory(std::make_shared<FD>(_body.directory_fd));
				_body.directory_fd = -1;
			} else {
				code = -ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} catch (std::system_error err) {
		code = -err.code().value();
	} catch (...) {
		code = std::numeric_limits<int>::min();
	}

	_sendReply(code);
};

void DarlingServer::Call::MldrPath::processCall() {
	int code = 0;
	uint64_t fullLength = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto tmpstr = std::string(Config::defaultMldrPath).substr(0, _body.buffer_size - 1);
			auto len = std::min(tmpstr.length() + 1, _body.buffer_size);

			fullLength = process->vchrootPath().length();

			if (!process->writeMemory(_body.buffer, tmpstr.c_str(), len, &code)) {
				// writeMemory returns a positive error code, but we want a negative one
				code = -code;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
};

void DarlingServer::Call::ThreadGetSpecialReplyPort::processCall() {
	_sendReply(0, dtape_thread_get_special_reply_port());
};

void DarlingServer::Call::MkTimerCreate::processCall() {
	_sendReply(0, dtape_mk_timer_create());
};

void DarlingServer::Call::PthreadKill::processCall() {
	int code = 0;

	if (auto targetThread = Thread::threadForPort(_body.thread_port)) {
		try {
			targetThread->sendSignal(_body.signal);
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PthreadCanceled::processCall() {
	int code = 0;

	callLog.warning() << "TODO: " << __PRETTY_FUNCTION__ << callLog.endLog;
	code = -ENOSYS;

	_sendReply(code);
};

void DarlingServer::Call::PthreadMarkcancel::processCall() {
	int code = 0;

	if (auto targetThread = Thread::threadForPort(_body.thread_port)) {
		callLog.warning() << "TODO: " << __PRETTY_FUNCTION__ << callLog.endLog;
		code = -ENOSYS;
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::KqchanMachPortOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::MachPort>(process, _body.port_name, _body.receive_buffer, _body.receive_buffer_size, _body.saved_filter_flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the port
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::KqchanProcOpen::processCall() {
	int code = 0;
	int socket = -1;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			auto kqchan = std::make_shared<Kqchan::Process>(process, _body.pid, _body.flags);

			try {
				socket = kqchan->setup();
			} catch (std::system_error e) {
				code = -e.code().value();
			} catch (...) {
				// just report that we couldn't find the process
				code = -ESRCH;
			}

			process->registerKqchan(kqchan);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, socket);
};

void DarlingServer::Call::ForkWaitForChild::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			// the child inherits our task's special ports (e.g. the bootstrap port) when it
			// checks in, so the parent must not return from fork() before that. if a signal
			// interrupted the wait, have the caller wait again; the child's check-in will
			// still raise the semaphore.
			if (!process->waitForChildAfterFork()) {
				code = -EINTR;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::Sigprocess::processCall() {
	int code = 0;
	int newBSDSignal = 0;

	if (auto thread = _thread.lock()) {
		try {
			thread->processSignal(_body.bsd_signal_number, _body.linux_signal_number, _body.code, _body.signal_address, _body.thread_state, _body.float_state);
			newBSDSignal = thread->pendingSignal();
		} catch (std::system_error e) {
			code = -e.code().value();
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, newBSDSignal);
};

void DarlingServer::Call::TaskIs64Bit::processCall() {
	int code = 0;
	bool is64Bit = false;

	if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.id)) {
		auto targetProcess = *maybeTargetProcess;
		is64Bit = targetProcess->is64Bit();
	} else {
		code = -ESRCH;
	}

	_sendReply(code, is64Bit);
};

void DarlingServer::Call::InterruptEnter::processCall() {
	Thread::_handleInterruptEnterForCurrentThread();

	_sendReply(0);
};

void DarlingServer::Call::InterruptExit::processCall() {
	auto thread = _thread.lock();

	dtape_thread_sigexc_exit(thread->_dtapeThread);

	_sendReply(0);

	{
		std::unique_lock lock(thread->_rwlock);

		auto tmp = std::move(thread->_interrupts.top());

		thread->_interrupts.pop();

		if (tmp.savedReply) {
			callLog.debug() << *thread << ": Going to send saved reply" << callLog.endLog;
			Server::sharedInstance().sendMessage(std::move(*tmp.savedReply));
			tmp.savedReply = std::nullopt;
		}
	}
};

void DarlingServer::Call::ConsoleOpen::processCall() {
	static Log consoleLog("console");

	int code = 0;
	int sockets[2] = { -1, -1 };

	// we don't really need bidirectional communication, so a pipe would suffice,
	// except that when you set O_NONBLOCK on one side of a pipe, it is set for both.

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
		int err = errno;
		callLog.warning() << __PRETTY_FUNCTION__ << ": socketpair failed with " << err << callLog.endLog;

		// just report EMFILE for the peer
		code = EMFILE;
	} else {
		// make our side non-blocking
		int flags = fcntl(sockets[0], F_GETFL);
		if (flags < 0) {
			code = -errno;
		} else {
			flags |= O_NONBLOCK;
			if (fcntl(sockets[0], F_SETFL, flags) < 0) {
				code = -errno;
			} else {
				// now monitor it
				auto fd = std::make_shared<FD>(sockets[0]);
				std::weak_ptr<Process> weakProcess;

				if (auto thread = _thread.lock()) {
					if (auto process = thread->process()) {
						weakProcess = process;
					}
				}

				Server::sharedInstance().addMonitor(std::make_shared<Monitor>(fd, Monitor::Event::Readable | Monitor::Event::HangUp, false, false, [fd, weakProcess](std::shared_ptr<Monitor> monitor, Monitor::Event events) {
					auto proc = weakProcess.lock();

					if (!proc || static_cast<uint64_t>(events & Monitor::Event::HangUp) != 0) {
						Server::sharedInstance().removeMonitor(monitor);
						return;
					}

					if (static_cast<uint64_t>(events & Monitor::Event::Readable) != 0) {
						std::stringstream data;
						while (true) {
							char buf[128];
							auto count = read(fd->fd(), buf, sizeof(buf) - 1);
							if (count <= 0) {
								break;
							}
							buf[count] = '\0';
							data << buf;
						}
						consoleLog.info() << *proc << ": " << data.rdbuf();
					}
				}));
			}
		}
	}

	if (code != 0) {
		if (sockets[0] >= 0) {
			close(sockets[0]);
			sockets[0] = -1;
		}
		if (sockets[1] >= 0) {
			close(sockets[1]);
			sockets[1] = -1;
		}
	}
	_sendReply(code, sockets[1]);
};

void DarlingServer::Call::SetDyldInfo::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			dtape_task_set_dyld_info(process->_dtapeTask, _body.address, _body.length);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::StopAfterExec::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->setStartSuspended(true);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

// x86Sim: see Process::setSpawnExec
void DarlingServer::Call::SpawnExec::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			process->setSpawnExec(true);
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetTracer::processCall() {
	int code = 0;
	std::shared_ptr<Process> targetProcess = nullptr;
	std::shared_ptr<Process> tracerProcess = nullptr;

	if (_body.target == 0) {
		if (auto thread = _thread.lock()) {
			targetProcess = thread->process();
		}
	} else {
		if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.target)) {
			targetProcess = *maybeTargetProcess;
		}
	}

	if (targetProcess) {
		if (_body.tracer == 0) {
			// leave tracer process as nullptr
		} else {
			if (auto maybeTracerProcess = processRegistry().lookupEntryByNSID(_body.tracer)) {
				tracerProcess = *maybeTracerProcess;
			} else {
				// intentionally not negated because this is not an internal error;
				// this is a perfectly valid case
				code = ESRCH;
			}
		}

		if (code == 0) {
			if (!targetProcess->setTracerProcess(tracerProcess)) {
				// again, not negated because this isn't an internal error;
				// simply indicates there was already a tracer set for the target
				code = EPERM;
			}
		}
	} else {
		// ditto from before
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::TidForThread::processCall() {
	int code = 0;
	int32_t tid = 0;

	if (auto thread = Thread::threadForPort(_body.thread)) {
		tid = thread->nsid();
	} else {
		// might be user error (e.g. invalid port number or dead thread), so don't negate it
		code = ESRCH;
	}

	_sendReply(code, tid);
};

void DarlingServer::Call::PtraceSigexc::processCall() {
	int code = 0;

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.target)) {
		auto process = *maybeProcess;

		dtape_task_set_sigexc_enabled(process->_dtapeTask, _body.enabled);
		dtape_task_try_resume(process->_dtapeTask);
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::PtraceThupdate::processCall() {
	int code = 0;

	if (auto maybeThread = threadRegistry().lookupEntryByNSID(_body.target)) {
		auto thread = *maybeThread;

		thread->setPendingSignal(_body.signum);
	} else {
		// not negated because this isn't an internal error
		code = ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::ThreadSuspended::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		thread->waitWhileUserSuspended(_body.thread_state, _body.float_state);
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::S2CPerform::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		callLog.debug() << *thread << ": s2c_perform: giving green light" << callLog.endLog; // x86Sim
		// x86Sim (willi/darlingserver#14): the request this green light answers, taken with the two semaphores under
		// the lock and retained (notifyDead() and the release destroy them). With no request, the signal is stale: nothing
		// waits for this green light, so it's answered at once.
		dtape_semaphore_t* enterSemaphore = nullptr;
		dtape_semaphore_t* exitSemaphore = nullptr;
		{
			std::unique_lock lock(thread->_rwlock);
			if (thread->_s2cRequest != 0 && thread->_s2cInterruptEnterSemaphore && thread->_s2cInterruptExitSemaphore) {
				thread->_s2cTaken = std::exchange(thread->_s2cRequest, 0);
				enterSemaphore = thread->_s2cInterruptEnterSemaphore;
				exitSemaphore = thread->_s2cInterruptExitSemaphore;
				dtape_semaphore_retain(enterSemaphore);
				dtape_semaphore_retain(exitSemaphore);
			}
		}
		if (enterSemaphore) {
			dtape_semaphore_up(enterSemaphore);
			dtape_semaphore_down_simple(exitSemaphore);
			dtape_semaphore_release(enterSemaphore);
			dtape_semaphore_release(exitSemaphore);
		} else {
			callLog.warning() << *thread << ": s2c_perform: stale S2C signal, no request" << callLog.endLog;
		}
		callLog.debug() << *thread << ": s2c_perform: resuming" << callLog.endLog; // x86Sim
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
};

void DarlingServer::Call::SetExecutablePath::processCall() {
	int code = 0;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			std::string tmpstr;
			tmpstr.resize(_body.buffer_size);
			if (!process->readMemory((uintptr_t)_body.buffer, tmpstr.data(), _body.buffer_size, &code)) {
				code = -code;
			} else {
				process->setExecutablePath(tmpstr.c_str());
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code);
}

void DarlingServer::Call::GetExecutablePath::processCall() {
	int code = 0;
	uint64_t fullLength;

	if (auto callingThread = _thread.lock()) {
		if (auto callingProcess = callingThread->process()) {
			if (auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_body.pid)) {
				auto targetProcess = *maybeTargetProcess;
				auto path = targetProcess->executablePath();
				auto len = std::min(path.length() + 1, _body.buffer_size);
				if (!callingProcess->writeMemory((uintptr_t)_body.buffer, path.c_str(), len, &code)) {
					code = -code;
				}
				fullLength = path.length();
			} else {
				// not negated because this is an acceptable case.
				// e.g. the target process may have died before the call was processed.
				code = ESRCH;
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, fullLength);
}

void DarlingServer::Call::Groups::processCall() {
	int code = 0;
	std::vector<uint32_t> oldGroups;

	if (auto thread = _thread.lock()) {
		if (auto process = thread->process()) {
			oldGroups = process->groups();

			if (_body.new_groups != 0 && _body.new_group_count > 0) {
				std::vector<uint32_t> newGroups;
				newGroups.resize(_body.new_group_count);

				if (!process->readMemory((uintptr_t)_body.new_groups, newGroups.data(), newGroups.size() * sizeof(uint32_t), &code)) {
					code = -code;
				} else {
					process->setGroups(newGroups);
				}
			}

			if (code == 0 && _body.old_groups != 0 && _body.old_group_space > 0) {
				auto len = std::min(oldGroups.size(), _body.old_group_space) * sizeof(uint32_t);
				if (!process->writeMemory((uintptr_t)_body.old_groups, oldGroups.data(), len, &code)) {
					code = -code;
				}
			}
		} else {
			code = -ESRCH;
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, oldGroups.size());
};

void DarlingServer::Call::DebugListProcesses::processCall() {
	int code = 0;
	auto processes = processRegistry().copyEntries();
	int pipes[2] = {-1, -1};

	code = pipe(pipes);
	if (code == 0) {
		for (const auto& process: processes) {
			dserver_debug_process_t debugProcess;
			debugProcess.pid = process->nsid();
			debugProcess.port_count = dtape_debug_task_port_count(process->_dtapeTask);
			write(pipes[1], &debugProcess, sizeof(debugProcess));
		}

		close(pipes[1]);
	}

	_sendReply(code, processes.size(), pipes[0]);
};

void DarlingServer::Call::DebugListPorts::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_task_list_ports(process->_dtapeTask, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMembers::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_portset_list_members(process->_dtapeTask, _body.portset, [](void* context, const dtape_debug_port_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_port_t debugPort;

				debugPort.port_name = port->name;
				debugPort.rights = port->rights;
				debugPort.refs = port->refs;
				debugPort.messages = port->messages;

				write(writeFD, &debugPort, sizeof(debugPort));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

void DarlingServer::Call::DebugListMessages::processCall() {
	int code = 0;
	uint64_t portCount = 0;
	int pipes[2] = {-1, -1};

	if (auto maybeProcess = processRegistry().lookupEntryByNSID(_body.process)) {
		auto process = *maybeProcess;

		code = pipe(pipes);
		if (code == 0) {
			portCount = dtape_debug_port_list_messages(process->_dtapeTask, _body.port, [](void* context, const dtape_debug_message_t* port) {
				int& writeFD = *(int*)context;
				dserver_debug_message_t debugMessage;

				debugMessage.sender = port->sender;
				debugMessage.size = port->size;

				write(writeFD, &debugMessage, sizeof(debugMessage));

				return true;
			}, &pipes[1]);
		}
	} else {
		code = -ESRCH;
	}

	_sendReply(code, portCount, pipes[0]);
};

DSERVER_CLASS_SOURCE_DEFS;
