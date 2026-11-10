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

#include "darlingserver/registry.hpp"
#include <darlingserver/thread.hpp>
#include <darlingserver/process.hpp>
#include <darlingserver/call.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/logging.hpp>
#include <filesystem>
#include <fstream>

#include <sys/mman.h>
#include <signal.h>

#include <darlingserver/duct-tape.h>
#include <atomic>

#include <sys/syscall.h>

#if DSERVER_ASAN
	#include <sanitizer/asan_interface.h>
#endif

#include <rtsig.h>

#include <assert.h>

#include <limits>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <vector>
#include <utility> // x86Sim
#include <atomic> // x86Sim

// 64KiB should be enough for us
// x86Sim: microthread context switches without glibc's rt_sigprocmask per getcontext()/setcontext() (src/fastcontext.cpp)
extern "C" int dserver_getcontext(ucontext_t* ucp) __attribute__((returns_twice));
extern "C" int dserver_setcontext(const ucontext_t* ucp);
#if !DSERVER_ASAN
#define getcontext dserver_getcontext
#define setcontext dserver_setcontext
#endif

#define THREAD_STACK_SIZE (64 * 1024ULL)
#define USE_THREAD_GUARD_PAGES 1
#define IDLE_THREAD_STACK_COUNT 8

static thread_local std::shared_ptr<DarlingServer::Thread> currentThreadVar = nullptr;
static thread_local bool returningToThreadTop = false;
static thread_local ucontext_t backToThreadTopContext;
static thread_local libsimple_lock_t* unlockMeWhenSuspending = nullptr;
static thread_local std::function<void()> currentContinuation = nullptr;

/**
 * Our microthreads use cooperative multitasking, so we don't really use interrupts per-se.
 * Rather, this is an indication to our cooperative scheduler that the microthread is doing something and
 * expects to continue to have control of the executing thread. If it calls a function/method that
 * would cause it to relinquish control of the thread, this should be considered an error.
 *
 * This is primarily of use for debugging duct-tape code and ensuring certain assumptions made in the duct-tape code hold true.
 */
static thread_local uint64_t interruptDisableCount = 0;

#if DSERVER_ASAN
	static thread_local void* asanOldFakeStack = nullptr;
	static thread_local const void* asanOldStackBottom = nullptr;
	static thread_local size_t asanOldStackSize = 0;
#endif

static DarlingServer::Log threadLog("thread");

DarlingServer::StackPool DarlingServer::Thread::stackPool(IDLE_THREAD_STACK_COUNT, THREAD_STACK_SIZE, USE_THREAD_GUARD_PAGES);

DarlingServer::Thread::Thread(std::shared_ptr<Process> process, NSID nsid, void* stackHint):
	_nstid(nsid),
	_process(process)
{
	_tid = -1;

	for (const auto& entry: std::filesystem::directory_iterator("/proc/" + std::to_string(process->id()) + "/task")) {
		std::ifstream statusFile(entry.path() / "status");
		std::string line;

		while (std::getline(statusFile, line)) {
			if (line.substr(0, sizeof("NSpid") - 1) == "NSpid") {
				auto pos = line.find_last_of('\t');
				std::string id;

				if (pos != line.npos) {
					id = line.substr(pos + 1);
				}

				if (id.empty()) {
					throw std::runtime_error("Failed to parse thread ID");
				}

				if (std::stoi(id) != _nstid) {
					continue;
				}

				_tid = std::stoi(entry.path().filename().string());

				break;
			}
		}
	}

	// if we can't determine the thread id from procfs, try some other more costly methods.
	if (_tid == -1) {
		std::vector<pid_t> ids;
		auto& registry = threadRegistry();
		for (const auto& entry: std::filesystem::directory_iterator("/proc/" + std::to_string(process->id()) + "/task")) {
			pid_t currentId = std::stoi(entry.path().filename().string());
			// Skip threads that are already registered, as we're sure they're not the ones we want.
			if (registry.lookupEntryByID(currentId).has_value()) {
				continue;
			}
			ids.push_back(currentId);
		}

		// we're sure this is the thread we want as this is the only unregistered thread.
		if (ids.size() == 1) {
			_tid = ids[0];
		} else if (stackHint != nullptr) {
			pid_t chosenId = -1;
			intptr_t nearest = std::numeric_limits<intptr_t>::max();

			for (auto id : ids) {
				if (ptrace(PTRACE_ATTACH, id, 0, 0) == -1) {
					continue;
				}

				int status;
				int waitStatus = waitpid(id, &status, 0);

				if (waitStatus < 0) {
					continue;
				}

				struct user_regs_struct regs;
				if (ptrace(PTRACE_GETREGS, id, 0, &regs) == -1) {
					continue;
				}

#ifdef __x86_64__
				intptr_t stackDiff = (intptr_t)stackHint - (intptr_t)regs.rsp;
				if (stackDiff >= 0 && stackDiff < nearest) {
#else
	#warning Unsupported architecture
				if (true) {
#endif
					chosenId = id;
					nearest = stackDiff;
				}

				// this is critical: we're tracing a process but cannot detach from it, and it'll not run normally.
				if (ptrace(PTRACE_DETACH, id, 0, 0) == -1) {
					throw std::system_error(errno, std::generic_category(), "Failed to detach from process.");
				}
			}

			_tid = chosenId;
		}
	}

	if (_tid == -1) {
		throw std::system_error(ESRCH, std::generic_category(), "Failed to find thread ID within darlingserver's namespace");
	}

	// NOTE: it's okay to use raw `this` without a shared pointer because the duct-taped thread will always live for less time than this Thread instance
	_dtapeThread = dtape_thread_create(process->_dtapeTask, _nstid, this);
	_s2cPerformSempahore = dtape_semaphore_create(process->_dtapeTask, 1);
	_s2cReplySempahore = dtape_semaphore_create(process->_dtapeTask, 0);
	_s2cInterruptEnterSemaphore = dtape_semaphore_create(process->_dtapeTask, 0);
	_s2cInterruptExitSemaphore = dtape_semaphore_create(process->_dtapeTask, 0);

	threadLog.info() << "New thread created with ID " << _tid << " and NSID " << _nstid << " for process with ID " << (process ? process->id() : -1) << " and NSID " << (process ? process->nsid() : -1);
};

DarlingServer::Thread::Thread(KernelThreadConstructorTag tag):
	_tid(-1),
	_process(Process::kernelProcess())
{
	static uint64_t kernelThreadIDCounter = DTAPE_KERNEL_THREAD_ID_THRESHOLD;
	static std::mutex kernelThreadIDCounterLock;

	std::unique_lock idLock(kernelThreadIDCounterLock);
	_nstid = kernelThreadIDCounter++;
	if (kernelThreadIDCounter == 0) {
		kernelThreadIDCounter = DTAPE_KERNEL_THREAD_ID_THRESHOLD;
	}
	idLock.unlock();

	_dtapeThread = dtape_thread_create(Process::kernelProcess()->_dtapeTask, _nstid, this);
};

void DarlingServer::Thread::registerWithProcess() {
	std::unique_lock lock(_process->_rwlock);
	_process->_threads[_nstid] = shared_from_this();
};

DarlingServer::Thread::~Thread() noexcept(false) {
	threadLog.info() << *this << ": thread being destroyed" << threadLog.endLog;

	if (_stack.isValid()) {
		stackPool.free(_stack);
	}

	if (!_process) {
		return;
	}

	std::unique_lock lock(_process->_rwlock);
	// x86Sim (willi/darlingserver#10): a newer thread with the same TID (Linux reused it before this one's release, which
	// is later now) may have replaced this one's entry, and may even have gone already: then it isn't ours to erase.
	// Compared by owner, as our own weak pointer has expired by now.
	auto it = _process->_threads.find(_nstid);
	auto self = weak_from_this();
	if (it == _process->_threads.end() || it->second.owner_before(self) || self.owner_before(it->second)) {
		threadLog.debug() << *this << ": its entry was replaced by a newer thread with its TID" << threadLog.endLog;
		return;
	}
	_process->_threads.erase(it);

	if (_process->_threads.empty()) {
		// if this was the last thread in the process, it has died, so unregister it.
		// this should already be handled by the process' pidfd monitor, but just in case, we also handle it here.
		lock.unlock();
		_process->notifyDead();
	}
};

DarlingServer::Thread::ID DarlingServer::Thread::id() const {
	return _tid;
};

DarlingServer::Thread::NSID DarlingServer::Thread::nsid() const {
	return _nstid;
};

DarlingServer::EternalID DarlingServer::Thread::eternalID() const {
	return _eid;
};

void DarlingServer::Thread::_setEternalID(EternalID eid) {
	_eid = eid;
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Thread::process() const {
	return _process;
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Thread::pendingCall() const {
	std::shared_lock lock(_rwlock);
	return _pendingCall;
};

bool DarlingServer::Thread::setPendingCall(std::shared_ptr<Call> newPendingCall) {
	std::unique_lock lock(_rwlock);
	if (newPendingCall && _pendingCall) {
		if (newPendingCall->number() == Call::Number::InterruptEnter) {
			// InterruptEnter calls can occur after we receive a call but before we start processing it,
			// so we need to handle this case gracefully. we do so by saving the interrupt and scheduling
			// it to be processed once the pending call becomes active and suspends or exits.
			// x86Sim (willi #13): doWork() schedules it then; the caller mustn't schedule the thread for it now
			_pendingInterrupts.push(newPendingCall);
			return false;
		} else {
			throw std::runtime_error("Thread's pending call overwritten while active");
		}
	}
	_pendingCall = newPendingCall;
	return true;
};

std::shared_ptr<DarlingServer::Call> DarlingServer::Thread::activeCall() const {
	std::shared_lock lock(_rwlock);
	return _activeCall;
};

void DarlingServer::Thread::makePendingCallActive() {
	std::unique_lock lock(_rwlock);
	_activeCall = _pendingCall;
	_pendingCall = nullptr;
};

void DarlingServer::Thread::_deactivateCallLocked(std::shared_ptr<Call> expectedCall) {
	if ((_interruptedForSignal ? _interrupts.top().interruptedCall : _activeCall).get() != expectedCall.get()) {
		throw std::runtime_error("Upon deactivating the active call found active/interrupted call != expected call");
	}
	(_interruptedForSignal ? _interrupts.top().interruptedCall : _activeCall) = nullptr;
};

void DarlingServer::Thread::deactivateCall(std::shared_ptr<Call> expectedCall) {
	std::unique_lock lock(_rwlock);
	_deactivateCallLocked(expectedCall);
};

DarlingServer::Address DarlingServer::Thread::address() const {
	std::shared_lock lock(_rwlock);
	return _address;
};

void DarlingServer::Thread::setAddress(Address address) {
	std::unique_lock lock(_rwlock);
	_address = address;
};

void DarlingServer::Thread::setThreadHandles(uintptr_t pthreadHandle, uintptr_t dispatchQueueAddress) {
	dtape_thread_set_handles(_dtapeThread, pthreadHandle, dispatchQueueAddress);
};

bool DarlingServer::Thread::waitingForReply() const {
	std::shared_lock lock(_rwlock);
	return !!_activeCall;
};

/*
 * IMPORTANT
 * ===
 *
 * The way that microthread handling/switching is done here is... not pretty, to say the least.
 * The problem is that, in order to use XNU's Mach IPC code, we need a way to interrupt execution of a "thread" and then resume from the same point.
 * Actual threads are too heavyweight, so instead we use our own form of microthreads with cooperative multitasking.
 * Using actual threads for each managed thread would be much simpler and far less hacky, but far more resource-intensive.
 */

static const auto microthreadLog = DarlingServer::Log("microthread");

// this runs in the context of the microthread (i.e. with the microthread's stack active)
void DarlingServer::Thread::microthreadWorker() {
#if DSERVER_ASAN
	__sanitizer_finish_switch_fiber(asanOldFakeStack, &asanOldStackBottom, &asanOldStackSize);
	asanOldFakeStack = nullptr;
#endif

	currentContinuation = nullptr;
	currentThreadVar->makePendingCallActive();
	currentThreadVar->_activeCall->processCall();

	if (currentThreadVar->_handlingInterruptedCall) {
		currentThreadVar->_didSyscallReturnDuringInterrupt = true;
#if DSERVER_ASAN
		__sanitizer_start_switch_fiber(NULL, currentThreadVar->_stack.base, currentThreadVar->_stack.size);
#endif
		setcontext(&currentThreadVar->_syscallReturnHereDuringInterrupt);
	} else {
#if DSERVER_ASAN
		// we're exiting normally, so we might not re-enter this microthread; tell ASAN to drop the fake stack
		__sanitizer_start_switch_fiber(NULL, asanOldStackBottom, asanOldStackSize);
#endif

		setcontext(&backToThreadTopContext);
	}
	__builtin_unreachable();
};

void DarlingServer::Thread::microthreadContinuation() {
#if DSERVER_ASAN
	__sanitizer_finish_switch_fiber(asanOldFakeStack, &asanOldStackBottom, &asanOldStackSize);
	asanOldFakeStack = nullptr;
#endif

	currentContinuation = currentThreadVar->_continuationCallback;
	// FIXME: we probably should never see `currentContinuation == nullptr`
	if (currentContinuation) {
		currentThreadVar->_continuationCallback = nullptr;
		currentContinuation();
		currentContinuation = nullptr;
	}

	if (currentThreadVar->_handlingInterruptedCall) {
		currentThreadVar->_didSyscallReturnDuringInterrupt = true;
#if DSERVER_ASAN
		__sanitizer_start_switch_fiber(NULL, currentThreadVar->_stack.base, currentThreadVar->_stack.size);
#endif
		setcontext(&currentThreadVar->_syscallReturnHereDuringInterrupt);
	} else {
#if DSERVER_ASAN
		// see microthreadWorker()
		__sanitizer_start_switch_fiber(NULL, asanOldStackBottom, asanOldStackSize);
#endif
		setcontext(&backToThreadTopContext);
	}
	__builtin_unreachable();
};

bool DarlingServer::Thread::claimScheduling() {
	return !_scheduled.exchange(true);
};

void DarlingServer::Thread::doWork() {
	// NOTE: this method MUST NOT use any local variables that require destructors.
	//       this method is actually major UB because the compiler is free to do whatever it likes with the stack,
	//       but we know what reasonable compilers (i.e. GCC and Clang) do with it and we're specifically targeting Clang, so it's okay for us.

	_rwlock.lock();

	// x86Sim (willi/darlingserver#13): off the work queue now; cleared under _rwlock (don't move it out)
	_scheduled = false;

	if (_deferralState != DeferralState::NotDeferred) {
		microthreadLog.debug() << _tid << "(" << _nstid << "): execution was deferred" << microthreadLog.endLog;
		_deferralState = DeferralState::DeferredPending;
		_rwlock.unlock();
		return;
	}

	if (_running) {
		// this is probably an error
		microthreadLog.warning() << _tid << "(" << _nstid << "): attempt to re-run already running microthread on another thread" << microthreadLog.endLog;
		_rwlock.unlock();
		return;
	}

	if (_terminating) {
		goto doneWorking;
	}

	if (_dead && !_activeCall) {
		// should be impossible, since this should be handled in `notifyDead`, but just in case
		_terminating = true;
		goto doneWorking;
	}

	_running = true;
	currentThreadVar = shared_from_this();
	dtape_thread_entering(_dtapeThread);

	returningToThreadTop = false;
	_rwlock.unlock();

	_runningCondvar.notify_all();

	getcontext(&backToThreadTopContext);

	if (returningToThreadTop) {
		// someone jumped back to the top of the microthread
		// (that means either the microthread has been suspended or it has finished)

#if DSERVER_ASAN
		__sanitizer_finish_switch_fiber(asanOldFakeStack, &asanOldStackBottom, &asanOldStackSize);
		asanOldFakeStack = nullptr;
#endif

		_rwlock.lock();

		if (!_suspended || _continuationCallback) {
			// we discard the old stack when either:
			//   * we exit normally (i.e. without suspending); this includes syscall returns.
			//   * or when we suspend with a continuation callback.
			stackPool.free(_stack);
		}

		//microthreadLog.debug() << _tid << "(" << _nstid << "): microthread returned to top" << microthreadLog.endLog;
		goto doneWorking;
	} else {
		returningToThreadTop = true;

		_rwlock.lock();

		if (!_pendingCallOverride && _pendingCall && _pendingCall->number() == Call::Number::InterruptEnter) {
			_interrupts.emplace();
			_interrupts.top().savedStack = _stack;
			_stack = StackPool::Stack();
			_interruptedContinuation = _continuationCallback;
			_continuationCallback = nullptr;
			_interrupts.top().interruptedCall = _activeCall;
			_activeCall = nullptr;
		}

		if (_continuationCallback && _pendingCall) {
			// we can only have one of the two
			// x86Sim (RAM 15): happens when an app is SIGKILLed while one of its threads waits with a continuation (the
			// iPhone Duo's training killed Safari / News / Health: darlingserver aborted and took every process of the
			// phone with it, SIGILL in each). The thread's new call wins; its old suspended call can never resume (its
			// stack is gone with a continuation) and is dropped instead of aborting the server.
			if (_pendingCallOverride) {
				throw std::runtime_error("Thread has both a pending call and a pending continuation");
			}
			microthreadLog.error() << _tid << "(" << _nstid << "): pending call " << static_cast<int>(_pendingCall->number()) << " and a pending continuation: continuation dropped" << microthreadLog.endLog;
			_continuationCallback = nullptr;
		}

		if (_suspended && (_pendingCallOverride || !_pendingCall)) {
			if (_pendingCallOverride) {
				microthreadLog.info() << _tid << "(" << _nstid << "): thread was suspended with a pending call override and is now resuming with a pending call" << microthreadLog.endLog;
			}
			// we were in the middle of processing a call and we need to resume now
			_suspended = false;
			_resumeContext.uc_link = &backToThreadTopContext;
			_rwlock.unlock();

			if (_continuationCallback) {
				// for continuations, we discard the old stack and start with a new one
				assert(!_stack.isValid());
				stackPool.allocate(_stack);

				// we also ahve to set up the resume context properly with the new stack
				_resumeContext.uc_stack.ss_sp = _stack.base;
				_resumeContext.uc_stack.ss_size = _stack.size;
				_resumeContext.uc_stack.ss_flags = 0;
				_resumeContext.uc_link = &backToThreadTopContext;
				makecontext(&_resumeContext, microthreadContinuation, 0);
			} else {
				// otherwise, we expect to have a valid stack to continue where we left off
				assert(_stack.isValid());
			}

#if DSERVER_ASAN
			__sanitizer_start_switch_fiber(&asanOldFakeStack, _stack.base, _stack.size);
#endif

			setcontext(&_resumeContext);
		} else {
			if (!_pendingCall) {
				// if we don't actually have a pending call, we have nothing to do
				goto doneWorking;
			}
			_suspended = false;
			_rwlock.unlock();

			// we might've had a valid stack if we're overwriting a previous suspension, so handle that.
			if (_stack.isValid()) {
				stackPool.free(_stack);
			}

			stackPool.allocate(_stack);

			ucontext_t newContext;
			getcontext(&newContext);
			newContext.uc_stack.ss_sp = _stack.base;
			newContext.uc_stack.ss_size = _stack.size;
			newContext.uc_stack.ss_flags = 0;
			newContext.uc_link = &backToThreadTopContext;
			makecontext(&newContext, microthreadWorker, 0);

#if DSERVER_ASAN
			__sanitizer_start_switch_fiber(&asanOldFakeStack, _stack.base, _stack.size);
#endif

			setcontext(&newContext);
		}

		// inform the compiler that it shouldn't do anything that would live past the setcontext calls
		__builtin_unreachable();
	}

doneWorking:
	// we must be holding `_rwlock` when we get here
	if (_running) {
		dtape_thread_exiting(_dtapeThread);
		currentThreadVar = nullptr;
		_running = false;
	}
	bool canRelease = false;
	if (_dead) {
		threadLog.debug() << *this << ": dead thread returning. active call? " << (!!_activeCall ? "true" : "false") << " terminating? " << (_terminating ? "true" : "false") << threadLog.endLog;
	}
	if (_dead && !_activeCall && !_terminating) {
		// this is the case when `notifyDead` notified us we were dead
		// but we had an active call and had to finish it first
		_terminating = true;
		canRelease = true;
	}
	if (_terminating && !_dead) {
		// this will not destroy our thread immediately;
		// the worker thread invoker still holds a reference on us
		_rwlock.unlock();
		notifyDead();
	} else {
		// if we have any pending interrupts, schedule them to be processed now
		// (we've just finished or suspended a call, so now's the time to handle interrupts)
		if (!_terminating && !_dead && !_pendingInterrupts.empty()) {
			if (_pendingCall) {
				throw std::runtime_error("Need to schedule interrupt for processing, but thread has pending call");
			}

			_pendingCall = _pendingInterrupts.front();
			_pendingInterrupts.pop();

			Server::sharedInstance().scheduleThread(shared_from_this());
		}
		else if (!_terminating && !_dead && _pendingCall && !_pendingCallOverride) {
			// x86Sim (willi/darlingserver#13 W1): a call that came in while this one ran may have found the thread
			// still running; nothing else would run it. The claim drops this if its own entry hasn't started.
			Server::sharedInstance().scheduleThread(shared_from_this());
		}

		_rwlock.unlock();
	}
	if (unlockMeWhenSuspending) {
		libsimple_lock_unlock(unlockMeWhenSuspending);
		unlockMeWhenSuspending = nullptr;
	}
	_runningCondvar.notify_all();
	if (canRelease) {
		_scheduleRelease();
	}
	return;
};

void DarlingServer::Thread::suspend(std::function<void()> continuationCallback, libsimple_lock_t* unlockMe) {
	if (this != currentThreadVar.get()) {
		throw std::runtime_error("Attempt to suspend thread other than current thread");
	}

	if (interruptDisableCount > 0) {
		throw std::runtime_error("Attempt to suspend thread while interrupts disabled");
	}

	_rwlock.lock();
	_suspended = true;
	_rwlock.unlock();

	unlockMeWhenSuspending = unlockMe;

	getcontext(&_resumeContext);

	_rwlock.lock();
	if (_suspended) {
		if (continuationCallback) {
			// when suspendeding with a continuation, the current continuation and call are discarded (since they can no longer be safely returned to)
			currentContinuation = nullptr;

			_continuationCallback = continuationCallback;
		}
		// jump back to the top of the microthread
		_rwlock.unlock();

#if DSERVER_ASAN
		// if we have a continuation, we don't expect to come back here
		__sanitizer_start_switch_fiber((continuationCallback) ? nullptr : &asanOldFakeStack, asanOldStackBottom, asanOldStackSize);
#endif

		setcontext(&backToThreadTopContext);
		__builtin_unreachable();
	} else {
		// we've been resumed

		// make sure we don't have a continuation when we get here;
		// if we do, that means that doWork() failed to do its job for the continuation case
		assert(!_continuationCallback);

		_rwlock.unlock();

#if DSERVER_ASAN
		__sanitizer_finish_switch_fiber(asanOldFakeStack, &asanOldStackBottom, &asanOldStackSize);
		asanOldFakeStack = nullptr;
#endif
	}
};

void DarlingServer::Thread::resume() {
	{
		std::shared_lock lock(_rwlock);
		if (!_suspended) {
			// maybe we should throw an error here?
			return;
		}
	}

	Server::sharedInstance().scheduleThread(shared_from_this());
};

void DarlingServer::Thread::terminate() {
	if (_process) {
		if (_process.get() != Process::kernelProcess().get()) {
			throw std::runtime_error("terminate() called on non-kernel thread");
		}
	} else {
		throw std::runtime_error("terminate() called on non-kernel thread");
	}

	_rwlock.lock();
	_terminating = true;

	if (currentThreadVar.get() == this) {
		// if it's the current thread, just suspend it;
		// when we return to the "top" of the microthread,
		// doWork() will see that it's terminating and clean up
		_rwlock.unlock();
		suspend();
		throw std::runtime_error("terminate() on current kernel thread returned");
	} else {
		// if it's not the current thread and it's not currently running, just tell it died;
		// it should die once the caller releases their reference(s) on us
		if (!_running) {
			_rwlock.unlock();
			notifyDead();
		} else {
			// otherwise, if it IS running, once it returns to the microthread "top" and sees `_terminating = true`, it'll unregister itself
			_rwlock.unlock();
		}
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::currentThread() {
	return currentThreadVar;
};

DarlingServer::Thread* DarlingServer::Thread::currentThreadRaw() {
	return currentThreadVar.get();
};

void DarlingServer::Thread::setupKernelThread(std::function<void()> startupCallback) {
	std::unique_lock lock(_rwlock);
	_continuationCallback = startupCallback;
	_suspended = true;
	getcontext(&_resumeContext);
};

void DarlingServer::Thread::startKernelThread(std::function<void()> startupCallback) {
	setupKernelThread(startupCallback);
	resume();
};

void DarlingServer::Thread::impersonate(std::shared_ptr<Thread> thread) {
	std::shared_ptr<Thread> oldThread;

	if (thread) {
		// prevent the thread from running while we're impersonating it
		// FIXME: this may lead to blocking natively while we're on a microthread.
		//        we would prefer to block using duct-taped facilities instead.
		{
			std::unique_lock lock(thread->_rwlock);
			thread->_deferLocked(true, lock);
			thread->_running = true;
		}
		thread->_runningCondvar.notify_all();
	}

	{
		std::unique_lock lock(_rwlock);
		oldThread = _impersonating;
		_impersonating = thread;
		_impersonatingRaw.store(thread.get(), std::memory_order_release);
	}

	if (oldThread) {
		{
			std::unique_lock lock(oldThread->_rwlock);
			oldThread->_running = false;
			oldThread->_undeferLocked(lock);
		}
		oldThread->_runningCondvar.notify_all();
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::impersonatingThread() const {
	std::shared_lock lock(_rwlock);
	return _impersonating;
};

void DarlingServer::Thread::interruptDisable() {
	++interruptDisableCount;
};

void DarlingServer::Thread::interruptEnable() {
	if (interruptDisableCount-- == 0) {
		throw std::runtime_error("interruptEnable() called when already enabled");
	}
};

void DarlingServer::Thread::syscallReturn(int resultCode) {
	if (!currentThreadVar) {
		throw std::runtime_error("syscallReturn() called with no current thread");
	}

	{
		auto call = (currentThreadVar->_interruptedForSignal) ? currentThreadVar->_interrupts.top().interruptedCall : currentThreadVar->_activeCall;
		if (!call || !call->isXNUTrap()) {
			throw std::runtime_error("Attempt to return from syscall on thread with no active syscall");
		}
		if (call->isBSDTrap()) {
			call->sendBSDReply(resultCode, currentThreadVar->_bsdReturnValue);
		} else {
			call->sendBasicReply(resultCode);
		}
	}

	if (currentThreadVar->_interruptedForSignal) {
		currentThreadVar->_didSyscallReturnDuringInterrupt = true;
#if DSERVER_ASAN
		if (currentThreadVar->_handlingInterruptedCall) {
			__sanitizer_start_switch_fiber(nullptr, currentThreadVar->_stack.base, currentThreadVar->_stack.size);
		}
#endif
		setcontext(&currentThreadVar->_syscallReturnHereDuringInterrupt);
		__builtin_unreachable();
	}

	// jump back to the top of the thread
#if DSERVER_ASAN
	__sanitizer_start_switch_fiber(nullptr, asanOldStackBottom, asanOldStackSize);
#endif
	setcontext(&backToThreadTopContext);
	__builtin_unreachable();
};

static std::queue<std::function<void()>> kernelAsyncRunnerQueue;

// we have to use a regular lock here because it needs to be lockable from both a microthread and normal thread context.
// additionally, it's only locked for brief periods.
//
// we use libsimple_lock_t so we can pass it to `suspend` to unlock it after suspending.
// XXX: we could use a std::mutex if we add an overload to `suspend` for it.
static libsimple_lock_t kernelAsyncRunnerQueueLock;
static dtape_semaphore_t* kernelAsyncRunnerQueueSempahore = nullptr;
static uint64_t kernelAsyncRunnersAvailable = 0;
static std::vector<std::shared_ptr<DarlingServer::Thread>> permanentKernelAsyncRunners;

#define MAX_PERMANENT_KERNEL_RUNNERS 10

static void kernelAsyncRunnerThreadWorker(bool permanent, std::shared_ptr<DarlingServer::Thread> self) {
	do {
		// we're going to wait for work; we're available now.
		libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
		++kernelAsyncRunnersAvailable;
		libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

		if (!dtape_semaphore_down_simple(kernelAsyncRunnerQueueSempahore)) {
			// we were interrupted. go again if we're permanent; otherwise, die.
			libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
			--kernelAsyncRunnersAvailable;
			libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

			if (permanent) {
				continue;
			} else {
				break;
			}
		}

		libsimple_lock_lock(&kernelAsyncRunnerQueueLock);

		if (kernelAsyncRunnerQueue.empty()) {
			// we didn't find any work (we were probably awoken spuriously).
			// go again if we're permanent; otherwise, die.
			--kernelAsyncRunnersAvailable;
			libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

			if (permanent) {
				continue;
			} else {
				break;
			}
		}

		// we're going to perform some work; we're no longer available
		--kernelAsyncRunnersAvailable;

		auto func = kernelAsyncRunnerQueue.front();
		kernelAsyncRunnerQueue.pop();

		libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

		// perform the work
		func();
	} while (permanent);

	self = nullptr;
	DarlingServer::Thread::currentThread()->terminate();
	__builtin_unreachable();
};

void DarlingServer::Thread::kernelAsync(std::function<void()> fn) {
	static bool inited = []() {
		kernelAsyncRunnerQueueSempahore = dtape_semaphore_create(Process::kernelProcess()->_dtapeTask, 0);
		return true;
	}();

	libsimple_lock_lock(&kernelAsyncRunnerQueueLock);
	kernelAsyncRunnerQueue.push(fn);
	// an available runner stays counted until it takes a job, so compare against the queued jobs, not 0: with one
	// runner available and two jobs queued, the second job would otherwise wait for the first to finish, forever if
	// the first waits on the second
	if (kernelAsyncRunnerQueue.size() > kernelAsyncRunnersAvailable) {
		// we need to get some work done, but there are no workers available.
		// if we have less workers than the max permanent number of workers,
		// let's spawn a permanent worker. otherwise, just spawn a temporary worker.
		auto thread = std::make_shared<Thread>(KernelThreadConstructorTag());
		auto permanent = permanentKernelAsyncRunners.size() < MAX_PERMANENT_KERNEL_RUNNERS;
		thread->startKernelThread(std::bind(kernelAsyncRunnerThreadWorker, permanent, thread));
		if (permanent) {
			permanentKernelAsyncRunners.push_back(std::move(thread));
		}
	}
	libsimple_lock_unlock(&kernelAsyncRunnerQueueLock);

	// increment the semaphore to let workers know there's work available.
	dtape_semaphore_up(kernelAsyncRunnerQueueSempahore);
};

void DarlingServer::Thread::kernelSync(std::function<void()> fn) {
	std::mutex mutex;
	std::condition_variable condvar;
	bool done = false;

	kernelAsync([&]() {
		fn();

		{
			std::unique_lock lock2(mutex);
			done = true;
		}

		// notify all, but there should only be one thread waiting
		condvar.notify_all();
	});

	// x86Sim: with inline work (no worker thread), the epoll thread is the one that runs the kernel microthread: run the
	// queue until it's done instead of waiting (only called outside microthreads, at startup)
	if (Server::sharedInstance().inlineWork()) {
		while (true) {
			{
				std::unique_lock lock(mutex);
				if (done) {
					break;
				}
			}
			if (Server::sharedInstance().drainWork() == 0) {
				std::this_thread::yield();
			}
		}
		return;
	}

	{
		std::unique_lock lock(mutex);
		condvar.wait(lock, [&]() {
			return done;
		});
	}
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Thread::threadForPort(uint32_t thread_port) {
	// prevent the target thread from dying by taking the global thread registry lock
	auto registryLock = threadRegistry().scopedLock();

	dtape_thread_t* thread_handle = dtape_thread_for_port(thread_port);
	if (!thread_handle) {
		return nullptr;
	}

	Thread* thread = static_cast<Thread*>(dtape_thread_context(thread_handle));
	if (!thread) {
		return nullptr;
	}

	return thread->shared_from_this();
};

void DarlingServer::Thread::loadStateFromUser(uint64_t threadState, uint64_t floatState) {
	int ret = dtape_thread_load_state_from_user(_dtapeThread, threadState, floatState);
	if (ret != 0) {
		throw std::system_error(-ret, std::generic_category());
	}
};

void DarlingServer::Thread::saveStateToUser(uint64_t threadState, uint64_t floatState) {
	int ret = dtape_thread_save_state_to_user(_dtapeThread, threadState, floatState);
	if (ret != 0) {
		throw std::system_error(-ret, std::generic_category());
	}
};

int DarlingServer::Thread::pendingSignal() const {
	std::shared_lock lock(_rwlock);
	return (_interrupts.empty()) ? 0 : _interrupts.top().signal;
};

int DarlingServer::Thread::setPendingSignal(int signal) {
	std::unique_lock lock(_rwlock);
	int pendingSignal;
	if (_interrupts.empty()) {
		throw std::runtime_error("Can't set pending signal with no active interrupts");
	} else {
		pendingSignal = _interrupts.top().signal;
		_interrupts.top().signal = signal;
	}
	return pendingSignal;
};

void DarlingServer::Thread::processSignal(int bsdSignalNumber, int linuxSignalNumber, int code, uintptr_t signalAddress, uintptr_t threadStateAddress, uintptr_t floatStateAddress) {
	try {
		loadStateFromUser(threadStateAddress, floatStateAddress);
	} catch (std::system_error e) {
		// x86Sim: as in waitWhileUserSuspended (process killed meanwhile)
		threadLog.warning() << *this << ": failed to load state from user in processSignal: " << e.code() << " (" << e.what() << ")" << threadLog.endLog;
		return;
	}

	{
		std::unique_lock lock(_rwlock);
		_interrupts.top().signal = 0;
		_processingSignal = true;
	}

	dtape_thread_process_signal(_dtapeThread, bsdSignalNumber, linuxSignalNumber, code, signalAddress);

	// LLDB commonly suspends the thread upon reception of an exception and assumes
	// that the thread will stay suspended after replying to the exception message,
	// until thread_resume() is called.
	dtape_thread_wait_while_user_suspended(_dtapeThread);

	{
		std::unique_lock lock(_rwlock);
		_processingSignal = false;
	}

	saveStateToUser(threadStateAddress, floatStateAddress);
};

void DarlingServer::Thread::handleSignal(int signal) {
	std::unique_lock lock(_rwlock);
	if (_processingSignal) {
		_interrupts.top().signal = signal;
	} else {
		throw std::runtime_error("Attempt to handle signal while not processing signal");
	}
};

void DarlingServer::Thread::setPendingCallOverride(bool pendingCallOverride) {
	std::unique_lock lock(_rwlock);
	_pendingCallOverride = pendingCallOverride;
};

/*
 * server-to-client (S2C) calls are used by darlingserver to invoke certain functions within managed processes
 * for which there is no in-server alterative.
 *
 * for example, memory allocation can only be done by the managed process itself; there is no Linux syscall to allocate memory in another process.
 * therefore, we have to ask the process to do it for us.
 *
 * an alternative to this system is ptrace. we can attach to the managed process and execute any function we like.
 * this is made even easier by the fact that we have our own code in the managed process, meaning we can help out the server by
 * providing thunks for it to execute that already include a debug trap.
 * the problem with this alternative is that there's no good way to tell when the child is done executing the function:
 *   * we could block with waitpid, but then that would block the worker thread for an indeterminate amount of time (and we want to avoid that).
 *   * we could have the main event loop poll periodically, but polling is undesirable.
 * additionally, if someone else is already ptracing that process, we lose the ability to execute code with this approach.
 * therefore, we have this RPC-based system instead.
 *
 * in order to perform an S2C call, however, the target thread MUST be waiting for a message from the server.
 * thus, when we want to perform an S2C call on a thread that isn't waiting for a message, we send it a real-time signal
 * to ask it to execute the S2C call. the signal is handled with the normal wrappers (interrupt_enter and interrupt_exit)
 * to properly handle the case when we may be accidentally interrupting an ongoing call in the thread (since we may have raced
 * with thread trying to perform a server call).
 */

static DarlingServer::Log s2cLog("s2c");

// x86Sim: ids for Thread::_s2cRequest (0 is none) (willi/darlingserver#14)
static std::atomic<uint64_t> s2cRequestCounter{0};

std::optional<DarlingServer::Message> DarlingServer::Thread::_s2cPerform(Message&& call, dserver_s2c_msgnum_t expectedReplyNumber, size_t expectedReplySize) {
	std::optional<Message> reply = std::nullopt;
	bool usingInterrupt = false;

	// x86Sim (willi/darlingserver#10): the thread may die while we wait for it, and its release destroys these, which
	// ends our waits. Retained, they stay valid here until we're done with them.
	struct RetainedSemaphore {
		dtape_semaphore_t* semaphore = nullptr;
		~RetainedSemaphore() { if (semaphore) dtape_semaphore_release(semaphore); };
	} performSemaphore, replySemaphore, enterSemaphore, exitSemaphore;
	{
		std::shared_lock lock(_rwlock);
		if (_dead || !_s2cPerformSempahore || !_s2cReplySempahore || !_s2cInterruptEnterSemaphore || !_s2cInterruptExitSemaphore) {
			throw std::system_error(ESRCH, std::generic_category(), "S2C call to a thread that has died");
		}
		for (auto [retained, semaphore]: { std::pair{&performSemaphore, _s2cPerformSempahore}, std::pair{&replySemaphore, _s2cReplySempahore}, std::pair{&enterSemaphore, _s2cInterruptEnterSemaphore}, std::pair{&exitSemaphore, _s2cInterruptExitSemaphore} }) {
			dtape_semaphore_retain(semaphore);
			retained->semaphore = semaphore;
		}
	}

	// make sure we're the only one performing an S2C call on this thread
	if (!dtape_semaphore_down_simple(performSemaphore.semaphore)) {
		// got interrupted while waiting
		if (isDead()) {
			throw std::system_error(ESRCH, std::generic_category(), "S2C call to a thread that has died");
		}
		return std::nullopt;
	}

	s2cLog.debug() << *this << ": Going to perform S2C call" << s2cLog.endLog;

	{
		std::unique_lock lock(_rwlock);

		// x86Sim (willi/darlingserver#14): mldr's checkin and thread-exit checkout get the signal, as mldr's RPC hooks
		// abort on an S2C call; libsystem's checkin and checkout (fork child, exec) serve one inline
		bool inMldrCall = _activeCall && _activeCall->madeByMldr();

		if (!_activeCall || inMldrCall) {
			// signal the thread that we want to perform an S2C call and wait for it to give us the green light
			if (_s2cInterruptEnterSemaphore != enterSemaphore.semaphore) {
				// it died since we retained them (notifyDead()), or an exec swapped them
				const bool dead = _dead;
				lock.unlock();
				dtape_semaphore_up(performSemaphore.semaphore);
				if (dead) {
					throw std::system_error(ESRCH, std::generic_category(), "S2C call to a thread that died before taking it");
				}
				return std::nullopt;
			}
			// the request S2CPerform takes; withdrawn below if we stop waiting
			const uint64_t request = ++s2cRequestCounter;
			_s2cRequest = request;
			lock.unlock();
			s2cLog.debug() << *this << ": Sending S2C signal" << s2cLog.endLog;
			usingInterrupt = true;
			try {
				sendSignal(LINUX_SIGRTMIN + 1);
			} catch (...) {
				lock.lock();
				if (_s2cRequest == request) {
					_s2cRequest = 0;
				}
				lock.unlock();
				// the next S2C call to this thread must not wait for ever for the perform semaphore
				dtape_semaphore_up(performSemaphore.semaphore);
				throw;
			}
			// a thread that dies without taking the signal never gives the green light: notifyDead() destroys the
			// enter semaphore, which ends this wait (as do the release and an exec's swap)
			if (!dtape_semaphore_down_simple(enterSemaphore.semaphore)) {
				lock.lock();
				const bool taken = _s2cTaken == request;
				if (_s2cRequest == request) {
					_s2cRequest = 0;
				}
				lock.unlock();
				// S2CPerform took it (it raises this semaphore next, unless it's gone): wait for that green light
				if (!(taken && dtape_semaphore_down_simple(enterSemaphore.semaphore))) {
					if (taken) {
						// S2CPerform waits for us
						dtape_semaphore_up(exitSemaphore.semaphore);
					}
					dtape_semaphore_up(performSemaphore.semaphore);
					if (isDead()) {
						// it never got the call: another thread can take it (Process::_performS2C())
						throw std::system_error(ESRCH, std::generic_category(), "S2C call to a thread that died before taking it");
					}
					return std::nullopt;
				}
			}
			s2cLog.debug() << *this << ": Got green light to perform S2C call" << s2cLog.endLog;
			lock.lock();
		} else if (currentThread().get() != this) {
			// we have an active call, so the client is waiting for a reply and is able to perform an S2C call,
			// but we're not the active thread. thus, in order to guarantee the client doesn't receive a reply
			// and stop waiting before we get a chance to perform our S2C call, let's make sure replies are deferred.
			_deferReplyForS2C = true;
		}

		call.setAddress(_address);
	}

	// at least for now, in order to wait for the S2C reply, we need the calling thread to be a microthread,
	// so that waiting on the duct-taped semaphore will work
	if (!currentThread()) {
		dtape_semaphore_up(performSemaphore.semaphore);
		if (usingInterrupt) {
			dtape_semaphore_up(exitSemaphore.semaphore); // x86Sim: don't leave the client in its S2C interrupt
		}
		throw std::runtime_error("Must be in a microthread (any microthread) to wait for S2C reply");
	}

	s2cLog.debug() << *this << ": Going to send S2C message" << s2cLog.endLog;

	// send the call
	Server::sharedInstance().sendMessage(std::move(call));

	// now let's wait for the reply
	if (!dtape_semaphore_down_simple(replySemaphore.semaphore)) {
		// x86Sim: interrupted (or the thread is gone) after the call went out. The client still answers it. Before, its
		// late reply sat in _s2cReply (with the semaphore raised): the next S2C call took it as its own, that call's
		// reply was the "duplicate" and was dropped, and with the signal path the client was left waiting in its
		// S2C interrupt for ever (exit semaphore never raised). Now a reply already here is discarded, else the late one
		// is marked to be dropped on arrival; deferred replies go out; the client is let go.
		bool replyHere;
		{
			std::unique_lock lock(_rwlock);
			replyHere = !!_s2cReply;
			if (replyHere) {
				_s2cReply = std::nullopt;
			} else {
				_s2cAbandonedReplies++;
			}
			if (_deferReplyForS2C) {
				_deferReplyForS2C = false;
				if (_deferredReply) {
					Server::sharedInstance().sendMessage(std::move(*_deferredReply));
					_deferredReply = std::nullopt;
				}
			}
		}
		if (replyHere) {
			// its up-count is (or is about to be) there: take it, so the next call doesn't return on it
			dtape_semaphore_down_simple(replySemaphore.semaphore);
		}
		s2cLog.warning() << *this << ": S2C call interrupted after it was sent; " << (replyHere ? "discarded its reply" : "its late reply will be dropped") << s2cLog.endLog;
		dtape_semaphore_up(performSemaphore.semaphore);
		if (usingInterrupt) {
			dtape_semaphore_up(exitSemaphore.semaphore);
		}
		return std::nullopt;
	}

	s2cLog.debug() << *this << ": Received S2C reply" << s2cLog.endLog;

	// extract the reply
	{
		std::unique_lock lock(_rwlock);

		if (!_s2cReply) {
			// impossible, but just in case
			dtape_semaphore_up(performSemaphore.semaphore);
			throw std::runtime_error("S2C reply semaphore incremented, but no reply present");
		}

		reply = std::move(_s2cReply);
		_s2cReply = std::nullopt;

		// if we had replies deferred, now's the time to send them
		if (_deferReplyForS2C) {
			_deferReplyForS2C = false;
			if (_deferredReply) {
				Server::sharedInstance().sendMessage(std::move(*_deferredReply));
				_deferredReply = std::nullopt;
			}
		}
	}

	s2cLog.debug() << *this << ": Done performing S2C call" << s2cLog.endLog;

	// we're done performing the call; allow others to have a chance at performing an S2C call on this thread
	dtape_semaphore_up(performSemaphore.semaphore);

	if (usingInterrupt) {
		// if we used the S2C signal to perform the call, then the s2c_perform call is currently waiting for us to finish;
		// let it know that we're done
		s2cLog.debug() << *this << ": Allowing thread to resume from S2C interrupt" << s2cLog.endLog;
		dtape_semaphore_up(exitSemaphore.semaphore);
	}

	// partially validate the reply

	if (reply->data().size() != expectedReplySize) {
		throw std::runtime_error("Invalid S2C reply: unxpected size");
	}

	auto replyHeader = reinterpret_cast<dserver_s2c_replyhdr_t*>(reply->data().data());
	if (replyHeader->s2c_number != expectedReplyNumber) {
		throw std::runtime_error("Invalid S2C reply: unexpected S2C reply number");
	}

	return std::move(*reply);
};

uintptr_t DarlingServer::Thread::_mmap(uintptr_t address, size_t length, int protection, int flags, int fd, off_t offset, int& outErrno) {
	// XXX: not sure if we want to force all allocations in 32-bit processes to be in the 32-bit address space.
	//      for now, we leave it up to the caller.
#if 0
	auto process = _process.lock();

	if (!process) {
		throw std::runtime_error("Cannot perform mmap without valid process");
	}

	if (process->architecture() == Process::Architecture::i386 || process->architecture() == Process::Architecture::ARM32) {
		flags |= MAP_32BIT;
	}
#endif

	Message callMessage(sizeof(dserver_s2c_call_mmap_t), (fd < 0) ? 0 : 1);
	auto call = reinterpret_cast<dserver_s2c_call_mmap_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_mmap;
	call->address = address;
	call->length = length;
	call->protection = protection;
	call->flags = flags;
	call->fd = (fd < 0) ? -1 : 0;
	call->offset = offset;

	if (fd >= 0) {
		auto dupfd = dup(fd);
		if (dupfd < 0) {
			outErrno = errno;
			return (uintptr_t)MAP_FAILED;
		}
		callMessage.pushDescriptor(dupfd);
	}

	s2cLog.debug() << "Performing _mmap with address=" << call->address << ", length=" << call->length << ", protection=" << call->protection << ", flags=" << call->flags << ", fd=" << call->fd << " (" << fd << ")" << ", offset=" << call->offset << s2cLog.endLog;

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_mmap, sizeof(dserver_s2c_reply_mmap_t));
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_mmap call interrupted" << s2cLog.endLog;
		outErrno = EINTR;
		return (uintptr_t)MAP_FAILED;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_mmap_t*>(replyMessage.data().data());

	s2cLog.debug() << "_mmap returned address=" << reply->address << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->address;
};

int DarlingServer::Thread::_munmap(uintptr_t address, size_t length, int& outErrno) {
	Message callMessage(sizeof(dserver_s2c_call_munmap_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_munmap_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_munmap;
	call->address = address;
	call->length = length;

	s2cLog.debug() << "Performing _munmap with address=" << call->address << ", length=" << call->length << s2cLog.endLog;

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_munmap, sizeof(dserver_s2c_reply_munmap_t));
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_munmap call interrupted" << s2cLog.endLog;
		outErrno = EINTR;
		return -1;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_munmap_t*>(replyMessage.data().data());

	s2cLog.debug() << "_munmap returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

int DarlingServer::Thread::_mprotect(uintptr_t address, size_t length, int protection, int& outErrno) {
	Message callMessage(sizeof(dserver_s2c_call_mprotect_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_mprotect_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_mprotect;
	call->address = address;
	call->length = length;
	call->protection = protection;

	s2cLog.debug() << "Performing _mprotect with address=" << call->address << ", length=" << call->length << ", protection=" << call->protection << s2cLog.endLog;

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_mprotect, sizeof(dserver_s2c_reply_mprotect_t));
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_mprotect call interrupted" << s2cLog.endLog;
		outErrno = EINTR;
		return -1;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_mprotect_t*>(replyMessage.data().data());

	s2cLog.debug() << "_mprotect returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

int DarlingServer::Thread::_msync(uintptr_t address, size_t size, int sync_flags, int& outErrno) {
	Message callMessage(sizeof(dserver_s2c_call_msync_t), 0);
	auto call = reinterpret_cast<dserver_s2c_call_msync_t*>(callMessage.data().data());

	call->header.call_number = dserver_callnum_s2c;
	call->header.s2c_number = dserver_s2c_msgnum_msync;
	call->address = address;
	call->size = size;
	call->sync_flags = sync_flags;

	s2cLog.debug() << "Performing _msync with address=" << call->address << ", size=" << call->size << ", sync_flags=" << call->sync_flags << s2cLog.endLog;

	auto maybeReplyMessage = _s2cPerform(std::move(callMessage), dserver_s2c_msgnum_msync, sizeof(dserver_s2c_reply_msync_t));
	if (!maybeReplyMessage) {
		s2cLog.debug() << "_msync call interrupted" << s2cLog.endLog;
		outErrno = EINTR;
		return -1;
	}

	auto replyMessage = std::move(*maybeReplyMessage);
	auto reply = reinterpret_cast<dserver_s2c_reply_msync_t*>(replyMessage.data().data());

	s2cLog.debug() << "_msync returned return_value=" << reply->return_value << ", errno_result=" << reply->errno_result << s2cLog.endLog;

	outErrno = reply->errno_result;
	return reply->return_value;
};

uintptr_t DarlingServer::Thread::allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite) {
	int err = 0;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (fixed && overwrite) {
		flags |= MAP_FIXED;
	} else if (fixed) {
		flags |= MAP_FIXED_NOREPLACE;
	}
	// x86Sim: an S2C call that is interrupted fails with EINTR (see _mmap); try again, as for mapFile()
	auto result = (uintptr_t)MAP_FAILED;
	for (int attempt = 0; attempt < 8; ++attempt) {
		result = _mmap(addressHint, pageCount * sysconf(_SC_PAGESIZE), protection, flags, -1, 0, err);
		if (result != (uintptr_t)MAP_FAILED || err != EINTR) break;
		s2cLog.warning() << *this << ": S2C mmap interrupted, retrying" << s2cLog.endLog;
	}
	if (result == (uintptr_t)MAP_FAILED) {
		throw std::system_error(err, std::generic_category(), "S2C mmap call failed");
	}
	return result;
};

void DarlingServer::Thread::freePages(uintptr_t address, size_t pageCount) {
	int err = 0;
	if (_munmap(address, pageCount * sysconf(_SC_PAGESIZE), err) < 0) {
		throw std::system_error(err, std::generic_category(), "S2C munmap call failed");
	}
};

uintptr_t DarlingServer::Thread::mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite, bool priv) {
	int err = 0;
	int flags = priv ? MAP_PRIVATE : MAP_SHARED;  // x86Sim: private = copy-on-write view of a memory entry
	if (fixed && overwrite) {
		flags |= MAP_FIXED;
	} else if (fixed) {
		flags |= MAP_FIXED_NOREPLACE;
	}
	// x86Sim: an S2C call that is interrupted (the thread took a signal, or the wait ended early) fails with EINTR, and
	// mach_vm_map() of a memory entry failed with it: a shared-memory map (xpc_shmem_map) in another process returned 0
	// now and then (WebKit's GPU process: "Failed to map IOSurface into user address space", FINDINGS 3.10/3.11).
	// XNU's vm_map doesn't fail that way. Try again; a late reply of an abandoned call is dropped (its mapping, if the
	// client still made one, stays unused).
	auto result = (uintptr_t)MAP_FAILED;
	for (int attempt = 0; attempt < 8; ++attempt) {
		result = _mmap(addressHint, pageCount * sysconf(_SC_PAGESIZE), protection, flags, fd, pageOffset * sysconf(_SC_PAGESIZE), err);
		if (result != (uintptr_t)MAP_FAILED || err != EINTR) break;
		s2cLog.warning() << *this << ": S2C mmap interrupted, retrying" << s2cLog.endLog;
	}
	if (result == (uintptr_t)MAP_FAILED) {
		throw std::system_error(err, std::generic_category(), "S2C mmap call failed");
	}
	return result;
};

void DarlingServer::Thread::changeProtection(uintptr_t address, size_t pageCount, int protection) {
	int err = 0;
	if (_mprotect(address, pageCount * sysconf(_SC_PAGESIZE), protection, err) < 0) {
		throw std::system_error(err, std::generic_category(), "S2C mprotect call failed");
	}
};

void DarlingServer::Thread::syncMemory(uintptr_t address, size_t size, int sync_flags) {
	int err = 0;
	if (_msync(address, size, sync_flags, err) < 0) {
		throw std::system_error(err, std::generic_category(), "S2C msync call failed");
	}
};

void DarlingServer::Thread::waitUntilRunning() {
	std::shared_lock lock(_rwlock);
	_runningCondvar.wait(lock, [&]() {
		return _running;
	});
};

void DarlingServer::Thread::waitUntilNotRunning() {
	std::shared_lock lock(_rwlock);
	_runningCondvar.wait(lock, [&]() {
		return !_running;
	});
};

void DarlingServer::Thread::_deferLocked(bool wait, std::unique_lock<std::shared_mutex>& lock) {
	if (_deferralState == DeferralState::NotDeferred) {
		_deferralState = DeferralState::DeferredNotPending;
	}

	if (wait) {
		_runningCondvar.wait(lock, [&]() {
			return !_running;
		});
	}
};

void DarlingServer::Thread::defer(bool wait) {
	std::unique_lock lock(_rwlock);
	_deferLocked(wait, lock);
};

void DarlingServer::Thread::_undeferLocked(std::unique_lock<std::shared_mutex>& lock) {
	DeferralState previousDeferralState;

	previousDeferralState = _deferralState;
	_deferralState = DeferralState::NotDeferred;

	if (previousDeferralState == DeferralState::DeferredPending) {
		Server::sharedInstance().scheduleThread(shared_from_this());
	}
};

void DarlingServer::Thread::undefer() {
	std::unique_lock lock(_rwlock);
	_undeferLocked(lock);
};

uint32_t* DarlingServer::Thread::bsdReturnValuePointer() {
	return &_bsdReturnValue;
};

void DarlingServer::Thread::logToStream(Log::Stream& stream) const {
	stream << "[T:" << _tid << "(" << _nstid << ")]";
};

void DarlingServer::Thread::pushCallReply(std::shared_ptr<Call> expectedCall, Message&& reply) {
	std::unique_lock lock(_rwlock);

	if (expectedCall) {
		_deactivateCallLocked(expectedCall);
	}

	if (_interruptedForSignal) {
		if (_interrupts.top().savedReply) {
			throw std::runtime_error("New reply would overwrite existing saved reply");
		}

		_interrupts.top().savedReply = std::move(reply);
	} else if (_deferReplyForS2C) {
		_deferredReply = std::move(reply);
	} else if (!_dead) {
		Server::sharedInstance().sendMessage(std::move(reply));
	}
};

DarlingServer::Thread::RunState DarlingServer::Thread::getRunState() const {
	auto process = this->process();
	if (!process || isDead()) {
		return RunState::Dead;
	}

	std::ifstream file("/proc/" + std::to_string(process->id()) + "/task/" + std::to_string(id()) + "/stat");
	std::string line;
	if (!std::getline(file, line)) {
		return RunState::Dead;
	}

	auto endOfComm = line.find(')');
	if (endOfComm == std::string::npos) {
		return RunState::Dead;
	}

	if (line.size() <= endOfComm + 2) {
		return RunState::Dead;
	}

	switch (line[endOfComm + 2]) {
		case 'R':
			return RunState::Running;
		case 'S':
			return RunState::Interruptible;
		case 'D':
			return RunState::Uninterruptible;
		case 'T':
			return RunState::Stopped;
		default:
			return RunState::Dead;
	}
};

void DarlingServer::Thread::waitWhileUserSuspended(uintptr_t threadStateAddress, uintptr_t floatStateAddress) {
	try {
		loadStateFromUser(threadStateAddress, floatStateAddress);
	} catch (std::system_error e) {
		// x86Sim: the process was killed between its suspension signal and this call (SIGKILL of a task-suspended app):
		// the read fails. Uncaught, this aborted darlingserver and took the whole phone down.
		threadLog.warning() << *this << ": failed to load state from user in waitWhileUserSuspended: " << e.code() << " (" << e.what() << ")" << threadLog.endLog;
		return;
	}
	dtape_thread_wait_while_user_suspended(_dtapeThread);
	try {
		saveStateToUser(threadStateAddress, floatStateAddress);
	} catch (std::system_error e) {
		// if we fail to save the state back to the process, that likely means the process died or was killed while waiting.
		// it's nothing to worry about. just log it and move on.
		threadLog.warning() << *this << ": failed to save state back to user in waitWhileUserSuspended: " << e.code() << " (" << e.what() << ")" << threadLog.endLog;
	}
};

void DarlingServer::Thread::sendSignal(int signal) const {
	if (isDead()) {
		return;
	}
	if (_process) {
		if (syscall(SYS_tgkill, _process->id(), id(), signal) < 0) {
			int code = errno;
			throw std::system_error(code, std::generic_category());
		}
	} else {
		throw std::system_error(ESRCH, std::generic_category());
	}
};

void DarlingServer::Thread::jumpToResume(void* stack, size_t stackSize) {
#if DSERVER_ASAN
	__sanitizer_start_switch_fiber(&asanOldFakeStack, stack, stackSize);
#endif
	setcontext(&_resumeContext);
	__builtin_unreachable();
};

void DarlingServer::Thread::notifyDead() {
	bool canRelease = false;
	dtape_semaphore_t* enterSemaphore = nullptr; // x86Sim (willi/darlingserver#14)
	dtape_thread_t* semaphoreOwner = nullptr;

	{
		std::unique_lock lock(_rwlock);
		if (_dead) {
			return;
		}

		threadLog.info() << *this << ": thread dying" << threadLog.endLog;
		_dead = true;

		if (!_activeCall) {
			// if we have no active call, we won't ever need to run again,
			// so set `_terminating` to make sure that doesn't happen
			_terminating = true;
			canRelease = true;
		}

		// x86Sim (willi/darlingserver#14): a dead thread never gives an S2C call the green light, and its release may wait
		// for its process: destroying the enter semaphore ends a waiting call at once, and it goes to another thread
		// (Process::_performS2C()). Destroyed only while a reference to the semaphores' task is held: this job holds
		// one to the duct-taped thread (and so its task) until it's done.
		enterSemaphore = std::exchange(_s2cInterruptEnterSemaphore, nullptr);
		if (enterSemaphore) {
			semaphoreOwner = _dtapeThread;
			dtape_thread_retain(semaphoreOwner);
		}
	}

	if (enterSemaphore) {
		kernelAsync([enterSemaphore, semaphoreOwner]() {
			dtape_semaphore_destroy(enterSemaphore);
			dtape_thread_release(semaphoreOwner);
		});
	}

	// keep ourselves alive until the duct-taped context is done
	_selfReference = shared_from_this();

	dtape_thread_dying(_dtapeThread);

	if (canRelease) {
		_scheduleRelease();
	} else {
		resume();
	}

	threadRegistry().unregisterEntry(shared_from_this());
};

bool DarlingServer::Thread::isDead() const {
	std::shared_lock lock(_rwlock);
	return _dead;
};

void DarlingServer::Thread::_dispose() {
	threadLog.debug() << *this << ": dispose thread context" << threadLog.endLog;
	_selfReference = nullptr;
};

void DarlingServer::Thread::notifyProcessDead() {
	// x86Sim (willi/darlingserver#10)
	notifyDead();

	bool release;
	{
		std::unique_lock lock(_rwlock);
		// dead before its process, and back at the top of its microthread (neither running nor suspended in its call):
		// nothing will run it again, and doneWorking didn't release it, as its call was left active
		release = _dead && !_running && !_suspended && !_releaseScheduled && _activeCall;
	}
	if (release) {
		threadLog.debug() << *this << ": died before its process; releasing it with the process" << threadLog.endLog;
		_scheduleRelease();
	}
};

void DarlingServer::Thread::_scheduleRelease() {
	{
		// x86Sim (willi/darlingserver#10): once: both doneWorking and notifyProcessDead() may get here
		std::unique_lock lock(_rwlock);
		if (_releaseScheduled) {
			return;
		}
		_releaseScheduled = true;
	}

	// schedule the duct-taped thread to be released
	// dtape_thread_release needs a microthread context, so we call it within a kernel microthread
	threadLog.debug() << *this << ": scheduling release" << threadLog.endLog;
	kernelAsync([self = shared_from_this()]() {
		// x86Sim (willi/darlingserver#10): taken under the lock, as _s2cPerform() retains them; destroying one ends
		// its waits there
		dtape_semaphore_t* semaphores[4];
		{
			std::unique_lock lock(self->_rwlock);
			semaphores[0] = std::exchange(self->_s2cPerformSempahore, nullptr);
			semaphores[1] = std::exchange(self->_s2cReplySempahore, nullptr);
			semaphores[2] = std::exchange(self->_s2cInterruptEnterSemaphore, nullptr);
			semaphores[3] = std::exchange(self->_s2cInterruptExitSemaphore, nullptr);
		}
		for (auto semaphore: semaphores) {
			if (semaphore) {
				dtape_semaphore_destroy(semaphore);
			}
		}
		dtape_thread_release(self->_dtapeThread);
		self->_dtapeThread = nullptr;
	});
};

static thread_local std::function<void()> interruptedContinuation = nullptr;

void DarlingServer::Thread::_handleInterruptEnterForCurrentThread() {
	// FIXME: this currently does not work properly if the thread was suspended waiting for a lock

	{
		std::unique_lock lock(currentThreadVar->_rwlock);

		if (currentThreadVar->_pendingSavedReply) {
			if (currentThreadVar->_interrupts.top().savedReply) {
				throw std::runtime_error("Pending saved reply would overwrite saved reply");
			}

			currentThreadVar->_interrupts.top().savedReply = std::move(*currentThreadVar->_pendingSavedReply);
			currentThreadVar->_pendingSavedReply = std::nullopt;
		}

		currentThreadVar->_interruptedForSignal = true;

		interruptedContinuation = currentThreadVar->_interruptedContinuation;
		currentThreadVar->_interruptedContinuation = nullptr;
	}

	dtape_thread_sigexc_enter(currentThreadVar->_dtapeThread);

	currentThreadVar->_didSyscallReturnDuringInterrupt = false;
	getcontext(&currentThreadVar->_syscallReturnHereDuringInterrupt);

	if (!currentThreadVar->_didSyscallReturnDuringInterrupt) {
		if (interruptedContinuation) {
			interruptedContinuation();
		} else if (currentThreadVar->_interrupts.top().interruptedCall) {
			currentThreadVar->_handlingInterruptedCall = true;
			currentThreadVar->_pendingCallOverride = true;
			currentThreadVar->jumpToResume(currentThreadVar->_interrupts.top().savedStack.base, currentThreadVar->_interrupts.top().savedStack.size);
		}
	} else if (currentThreadVar->_handlingInterruptedCall) {
#if DSERVER_ASAN
		const void* dummy;
		size_t dummy2;
		__sanitizer_finish_switch_fiber(nullptr, &dummy, &dummy2);
#endif

		currentThreadVar->_handlingInterruptedCall = false;
		currentThreadVar->_pendingCallOverride = false;
	}

	interruptedContinuation = nullptr;

	{
		std::unique_lock lock(currentThreadVar->_rwlock);

		if (currentThreadVar->_interrupts.top().savedStack.isValid()) {
			stackPool.free(currentThreadVar->_interrupts.top().savedStack);
		}

		currentThreadVar->_interruptedForSignal = false;
		currentThreadVar->_interrupts.top().interruptedCall = nullptr;
	}

	dtape_thread_sigexc_enter2(currentThreadVar->_dtapeThread);
};
