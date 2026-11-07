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

#include <darlingserver/process.hpp>
#include <darlingserver/registry.hpp>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>
#include <darlingserver/logging.hpp>

#include <fstream>
#include <regex>
#include <utility> // x86Sim
#include <vector> // x86Sim

#include <sys/mman.h>
#include <fcntl.h> // x86Sim
#include <sys/ioctl.h>
#include <linux/fs.h> // x86Sim: PROCMAP_QUERY
#ifndef PROCMAP_QUERY
// x86Sim: kernel headers before 6.11 (e.g. Ubuntu 24.04's, the release build) lack it; the ioctl is stable ABI and
// older running kernels answer ENOTTY (the maps parser below then takes over)
#ifndef PROCFS_IOCTL_MAGIC
#define PROCFS_IOCTL_MAGIC 'f'
#endif
enum procmap_query_flags {
	PROCMAP_QUERY_VMA_READABLE = 0x01,
	PROCMAP_QUERY_VMA_WRITABLE = 0x02,
	PROCMAP_QUERY_VMA_EXECUTABLE = 0x04,
	PROCMAP_QUERY_VMA_SHARED = 0x08,
	PROCMAP_QUERY_COVERING_OR_NEXT_VMA = 0x10,
	PROCMAP_QUERY_FILE_BACKED_VMA = 0x20,
};
struct procmap_query {
	__u64 size;
	__u64 query_flags;
	__u64 query_addr;
	__u64 vma_start;
	__u64 vma_end;
	__u64 vma_flags;
	__u64 vma_page_size;
	__u64 vma_offset;
	__u64 inode;
	__u32 dev_major;
	__u32 dev_minor;
	__u32 vma_name_size;
	__u32 build_id_size;
	__u64 vma_name_addr;
	__u64 build_id_addr;
};
#define PROCMAP_QUERY _IOWR(PROCFS_IOCTL_MAGIC, 17, struct procmap_query)
#endif
#include <string_view> // x86Sim
#include <cstring> // x86Sim

static DarlingServer::Log processLog("process");

DarlingServer::Process::Process(ID id, NSID nsid, Architecture architecture, int pipe):
	_pid(id),
	_nspid(nsid),
	_architecture(architecture)
{
	int pidfd = (pipe >= 0) ? pipe : syscall(SYS_pidfd_open, _pid, 0);
	if (pidfd < 0) {
		throw std::system_error(errno, std::generic_category(), "Failed to open pidfd for process");
	}

	_pidfd = std::make_shared<FD>(pidfd);

	// we could use stat instead of status, but it's more complicated with comm potentially getting in the way of parsing (it can include whitespace and parentheses)
	std::ifstream statusFile("/proc/" + std::to_string(id) + "/status");
	std::string line;

	std::shared_ptr<Process> parentProcess = nullptr;

	while (std::getline(statusFile, line)) {
		if (line.substr(0, sizeof("PPid") - 1) == "PPid") {
			auto pos = line.find_last_of('\t');
			std::string id;

			if (pos != line.npos) {
				id = line.substr(pos + 1);
			}

			if (id.empty()) {
				throw std::runtime_error("Failed to parse parent process ID");
			}

			if (auto maybeParentProcess = processRegistry().lookupEntryByID(std::stoi(id))) {
				parentProcess = *maybeParentProcess;
				_parentProcess = parentProcess;
			}

			break;
		}
	}

	if (parentProcess) {
		std::shared_lock parentLock(parentProcess->_rwlock);

		// inherit vchroot from parent process
		_vchrootDescriptor = parentProcess->_vchrootDescriptor;
		_cachedVchrootPath = parentProcess->_cachedVchrootPath;

		// inherit groups from parent process
		_groups = parentProcess->_groups;
	}

	// NOTE: see thread.cpp for why it's okay to use `this` here
	_dtapeTask = dtape_task_create(parentProcess ? parentProcess->_dtapeTask : nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
	_dtapeForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

	processLog.info() << "New process created with ID " << _pid << " and NSID " << _nspid;
};

DarlingServer::Process::Process(KernelProcessConstructorTag tag):
	_pid(-1),
	_nspid(0)
{
#if __x86_64__
	_architecture = Architecture::x86_64;
#elif __i386__
	_architecture = Architecture::i386;
#elif __aarch64__
	_architecture = Architecture::ARM64;
#elif __arm__
	_architecture = Architecture::ARM32;
#else
	#error Unknown architecture
#endif
	_dtapeTask = dtape_task_create(nullptr, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
};

DarlingServer::Process::~Process() {
	processLog.info() << *this << ": process being destroyed" << processLog.endLog;
};

DarlingServer::Process::ID DarlingServer::Process::id() const {
	return _pid;
};

DarlingServer::Process::NSID DarlingServer::Process::nsid() const {
	return _nspid;
};

DarlingServer::EternalID DarlingServer::Process::eternalID() const {
	return _eid;
};

void DarlingServer::Process::_setEternalID(EternalID eid) {
	_eid = eid;
};

std::vector<std::shared_ptr<DarlingServer::Thread>> DarlingServer::Process::threads() const {
	std::vector<std::shared_ptr<DarlingServer::Thread>> result;
	std::shared_lock lock(_rwlock);

	for (auto& [nsid, maybeThread]: _threads) {
		if (auto thread = maybeThread.lock()) {
			result.push_back(thread);
		}
	}

	return result;
};

std::string DarlingServer::Process::vchrootPath() const {
	std::shared_lock lock(_rwlock);
	return _cachedVchrootPath;
};

void DarlingServer::Process::setVchrootDirectory(std::shared_ptr<FD> directoryDescriptor) {
	std::unique_lock lock(_rwlock);
	_vchrootDescriptor = directoryDescriptor;

	char* tmp = new char[4096];

	auto fdPath = "/proc/self/fd/" + std::to_string(_vchrootDescriptor->fd());
	auto len = readlink(fdPath.c_str(), tmp, 4095);

	if (len < 0) {
		throw std::system_error(errno, std::generic_category(), "readlink");
	}

	tmp[len] = '\0';

	_cachedVchrootPath = std::string(tmp);
	delete[] tmp;
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::currentProcess() {
	auto thread = Thread::currentThread();
	if (!thread) {
		return nullptr;
	}

	return thread->process();
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::parentProcess() const {
	return _parentProcess.lock();
};

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::kernelProcess() {
	static std::shared_ptr<Process> process = [&]() {
		auto proc = std::make_shared<Process>(KernelProcessConstructorTag());
		processRegistry().registerEntry(proc, true);
		return proc;
	}();
	return process;
};

bool DarlingServer::Process::startSuspended() const {
	std::shared_lock lock(_rwlock);
	return _startSuspended;
};

void DarlingServer::Process::setStartSuspended(bool startSuspended) {
	std::unique_lock lock(_rwlock);
	_startSuspended = startSuspended;
};

// x86Sim: posix_spawn returns once the child has exec'd on macOS, so nobody can see that exec as NOTE_EXEC.
// Here the parent's posix_spawn returns at the Linux execve of mldr and the child registers the exec with us
// later, after the parent may have attached an EVFILT_PROC source: launchd_sim then took xpcproxy_sim's own
// start for the exec of the service and marked the job running before xpcproxy_sim had exec'd the real
// program, and runningboardd read the bundle properties of xpcproxy_sim for every extension ("could not find
// extension point", so PosterKit's rendering assertions were refused and the wallpaper never drew).
void DarlingServer::Process::setSpawnExec(bool spawnExec) {
	std::unique_lock lock(_rwlock);
	_spawnExec = spawnExec;
};

bool DarlingServer::Process::_readOrWriteMemory(bool isWrite, uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const {
	struct iovec local;
	struct iovec remote;
	const auto func = isWrite ? process_vm_writev : process_vm_readv;
	static DarlingServer::Log processMemoryAccessLog("procmem");

	if (isDead()) {
		processMemoryAccessLog.error()
			<< "Failed to "
			<< (isWrite ? "write " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< "): process dead"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = ESRCH;
		}
		return false;
	}

	local.iov_base = localBuffer;
	local.iov_len = length;

	remote.iov_base = (void*)remoteAddress;
	remote.iov_len = length;

	if (func(id(), &local, 1, &remote, 1, 0) < 0) {
		int code = errno;
		processMemoryAccessLog.error()
			<< "Failed to "
			<< (isWrite ? "write " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< "): "
			<< code
			<< " ("
			<< strerror(code)
			<< ")"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = code;
		}
		return false;
	} else {
		processMemoryAccessLog.debug()
			<< "Successfully "
			<< (isWrite ? "wrote " : "read ")
			<< length
			<< " byte(s) at 0x"
			<< std::hex << remoteAddress << std::dec
			<< " in process "
			<< id()
			<< " ("
			<< nsid()
			<< ")"
			<< processMemoryAccessLog.endLog;
		if (errorCode) {
			*errorCode = 0;
		}
		return true;
	}
};

bool DarlingServer::Process::readMemory(uintptr_t remoteAddress, void* localBuffer, size_t length, int* errorCode) const {
	return _readOrWriteMemory(false, remoteAddress, localBuffer, length, errorCode);
};

bool DarlingServer::Process::writeMemory(uintptr_t remoteAddress, const void* localBuffer, size_t length, int* errorCode) const {
	// the const_cast is safe; when writing to a process' memory, localBuffer is not modified
	return _readOrWriteMemory(true, remoteAddress, const_cast<void*>(localBuffer), length, errorCode);
};

void DarlingServer::Process::notifyCheckin(Architecture architecture) {
	std::unique_lock lock(_rwlock);

	bool didExec = _pendingReplacement;

	if (didExec) {
		// exec case

		processLog.info() << *this << ": replacing process with a new task (with architecture \"" << architectureToString(architecture) << "\")" << processLog.endLog;

		// clear all threads except the main thread
		std::shared_ptr<Thread> mainThread = nullptr;
		while (!_threads.empty()) {
			auto it = _threads.begin();
			auto thread = it->second.lock();
			lock.unlock();
			if (thread) {
				if (thread->_nstid == _nspid) {
					mainThread = thread;
				} else {
					thread->_process = nullptr;
					thread->notifyDead();
				}
			}
			lock.lock();
			_threads.erase(it);
		}
		if (!mainThread) {
			throw std::runtime_error("Main thread for process died?");
		}
		_threads[mainThread->nsid()] = mainThread;

		// update the process architecture
		_architecture = architecture;

		// replace the old task with a new task that inherits from it
		auto oldTask = _dtapeTask;
		auto newTask = dtape_task_create(oldTask, _nspid, this, static_cast<dserver_rpc_architecture_t>(_architecture));
		_dtapeTask = newTask;

		// now replace the main thread's duct-taped thread with a new one
		auto oldThread = mainThread->_dtapeThread;
		auto newThread = dtape_thread_create(_dtapeTask, mainThread->_nstid, mainThread.get());
		mainThread->_dtapeThread = newThread;

		// destroy the main thread's old S2C semaphores: x86Sim (willi/darlingserver#10/#14): taken under the thread's
		// lock, as _s2cPerform() retains them under it; a request on the old ones is void
		dtape_semaphore_t* oldS2CSemaphores[4];
		{
			std::unique_lock threadLock(mainThread->_rwlock);
			oldS2CSemaphores[0] = std::exchange(mainThread->_s2cPerformSempahore, nullptr);
			oldS2CSemaphores[1] = std::exchange(mainThread->_s2cReplySempahore, nullptr);
			oldS2CSemaphores[2] = std::exchange(mainThread->_s2cInterruptEnterSemaphore, nullptr);
			oldS2CSemaphores[3] = std::exchange(mainThread->_s2cInterruptExitSemaphore, nullptr);
			mainThread->_s2cRequest = 0;
			mainThread->_s2cAbandonedReplies = 0;
		}
		for (auto semaphore: oldS2CSemaphores) {
			if (semaphore) {
				dtape_semaphore_destroy(semaphore);
			}
		}

		// destroy the fork-wait semaphore
		dtape_semaphore_destroy(_dtapeForkWaitSemaphore);
		_dtapeForkWaitSemaphore = nullptr;

		// release the main thread's old duct-taped thread
		dtape_thread_release(oldThread);

		// release the old task
		dtape_task_release(oldTask);

		// create a new fork-wait semaphore for the new task
		_dtapeForkWaitSemaphore = dtape_semaphore_create(_dtapeTask, 0);

		// create new S2C semaphores for the main thread (x86Sim: set under its lock, willi/darlingserver#10)
		{
			auto performSemaphore = dtape_semaphore_create(_dtapeTask, 1);
			auto replySemaphore = dtape_semaphore_create(_dtapeTask, 0);
			auto enterSemaphore = dtape_semaphore_create(_dtapeTask, 0);
			auto exitSemaphore = dtape_semaphore_create(_dtapeTask, 0);
			std::unique_lock threadLock(mainThread->_rwlock);
			mainThread->_s2cPerformSempahore = performSemaphore;
			mainThread->_s2cReplySempahore = replySemaphore;
			mainThread->_s2cInterruptEnterSemaphore = enterSemaphore;
			mainThread->_s2cInterruptExitSemaphore = exitSemaphore;
		}
	} else {
		// fork case

		if (architecture != _architecture) {
			throw std::runtime_error("Impossible: parent process architecture != child process architecture on fork");
		}
	}

	_pendingReplacement = false;

	bool spawnExec = _spawnExec; // x86Sim
	_spawnExec = false;

	lock.unlock();

	if (didExec && !spawnExec) {
		// notify listeners that we have exec'd (i.e. been replaced)
		_notifyListeningKqchannels(NOTE_EXEC, 0);
	} else {
		// notify the parent process (if we have one) that we've arrived
		if (auto parent = _parentProcess.lock()) {
			// x86Sim: the parent may have died meanwhile; its fork-wait semaphore is then already destroyed (null),
			// and dtape_semaphore_up(NULL) took darlingserver and the whole container down (seen when a simulator
			// app's spawner exited while the app was checking in). Read it under the parent's lock (notifyDead clears
			// it under that lock).
			{
				std::shared_lock parentLock(parent->_rwlock);
				if (parent->_dtapeForkWaitSemaphore) {
					dtape_semaphore_up(parent->_dtapeForkWaitSemaphore);
				}
			}
			parent->_notifyListeningKqchannels(NOTE_FORK, nsid());
		}
	}
};

void DarlingServer::Process::setPendingReplacement() {
	std::unique_lock lock(_rwlock);

	processLog.info() << "Process " << id() << " (" << nsid() << ") is now pending replacement" << processLog.endLog;

	_pendingReplacement = true;
};

void DarlingServer::Process::registerKqchan(std::shared_ptr<Kqchan> kqchan) {
	std::unique_lock lock(_rwlock);

	_kqchannels[kqchan->_idForProcess()] = kqchan;
};

void DarlingServer::Process::unregisterKqchan(std::shared_ptr<Kqchan> kqchan) {
	std::unique_lock lock(_rwlock);

	_kqchannels.erase(kqchan->_idForProcess());
};

bool DarlingServer::Process::waitForChildAfterFork() {
	// this function is always called within a microthread
	return dtape_semaphore_down_simple(_dtapeForkWaitSemaphore);
};

void DarlingServer::Process::registerListeningKqchan(std::shared_ptr<Kqchan::Process> kqchan) {
	std::unique_lock lock(_rwlock);
	uintptr_t id = static_cast<std::shared_ptr<Kqchan>>(kqchan)->_idForProcess();
	_listeningKqchannels[id] = kqchan;
};

void DarlingServer::Process::unregisterListeningKqchan(uintptr_t kqchanID) {
	std::unique_lock lock(_rwlock);
	_listeningKqchannels.erase(kqchanID);
};

void DarlingServer::Process::_notifyListeningKqchannels(uint32_t event, int64_t data) {
	decltype(_listeningKqchannels) listeningKqchannels;

	// we do NOT want to be holding our rwlock when we notify the kqchannels; that can lead to deadlocks
	{
		std::shared_lock lock(_rwlock);
		listeningKqchannels = _listeningKqchannels;
	}

	for (auto& [id, maybeKqchan]: listeningKqchannels) {
		auto kqchan = maybeKqchan.lock();

		if (!kqchan) {
			continue;
		}

		kqchan->_notify(event, data);
	}
};

bool DarlingServer::Process::is64Bit() const {
	return _architecture == Architecture::x86_64 || _architecture == Architecture::ARM64;
};

DarlingServer::Process::Architecture DarlingServer::Process::architecture() const {
	return _architecture;
};

void DarlingServer::Process::logToStream(Log::Stream& stream) const {
	stream << "[P:" << _pid << "(" << _nspid << ")]";
};

DarlingServer::Process::MemoryInfo DarlingServer::Process::memoryInfo() const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryInfo");
	}

	MemoryInfo info {};
	std::ifstream file("/proc/" + std::to_string(_pid) + "/statm");

	if (!(file >> info.virtualSize >> info.residentSize)) {
		// the process died after the check above
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryInfo");
	}

	info.virtualSize *= sysconf(_SC_PAGESIZE);
	info.residentSize *= sysconf(_SC_PAGESIZE);

	// CHECKME: can different processes have different page sizes on Linux?
	info.pageSize = sysconf(_SC_PAGESIZE);

	// TODO
	info.regionCount = 0;

	return info;
};

// x86Sim: /proc/<pid>/maps is parsed by hand, not with std::regex. mach_make_memory_entry (every xpc_shmem, e.g.
// MTLSimDriver's command-buffer segments) and the memfd-for-region RPC look a region up here, and a simulator process
// has thousands of mappings: matching a regex against every line took ~75% of darlingserver's worker thread during
// CoreAnimation animations, which capped the frame rate. Only the line holding the address is parsed in full.
// Fields: start-end perms offset dev inode [path] (the path tells anonymous shared memory from file mappings).
static bool parseHex(const char*& p, const char* end, uintptr_t& out) {
	const char* start = p;
	uintptr_t v = 0;
	for (; p < end; ++p) {
		char c = *p;
		unsigned d;
		if (c >= '0' && c <= '9') d = c - '0';
		else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
		else break;
		v = (v << 4) | d;
	}
	out = v;
	return p != start;
}
static void skipSpaces(const char*& p, const char* end) { while (p < end && (*p == ' ' || *p == '\t')) ++p; }
static const char* skipField(const char* p, const char* end) { while (p < end && *p != ' ' && *p != '\t') ++p; return p; }

DarlingServer::Process::MemoryRegionInfo DarlingServer::Process::memoryRegionInfo(uintptr_t address) const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call memoryRegionInfo");
	}

	MemoryRegionInfo info;
	std::string path = "/proc/" + std::to_string(_pid) + "/maps";
	int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		processLog.warning() << *this << ": can't open \"" << path << "\"" << processLog.endLog;
		throw std::system_error(EFAULT, std::generic_category());
	}

	// x86Sim: ask the kernel for the one VMA (PROCMAP_QUERY, Linux 6.11+) instead of reading and parsing the
	// whole maps file (a 256 KB buffer and thousands of lines per call; 5-9% of darlingserver while scrolling,
	// called for every out-of-line memory and memory entry); older kernels fall through to the parser
	{
		static bool noQuery = false;
		if (!noQuery) {
			char name[4096];
			struct procmap_query q;
			memset(&q, 0, sizeof(q));
			q.size = sizeof(q);
			q.query_addr = address;
			q.query_flags = 0; // the VMA covering the address
			q.vma_name_addr = (uintptr_t)name;
			q.vma_name_size = sizeof(name);
			if (ioctl(fd, PROCMAP_QUERY, &q) == 0) {
				close(fd);
				info.startAddress = q.vma_start;
				info.pageCount = (q.vma_end - q.vma_start) / sysconf(_SC_PAGESIZE);
				info.mapOffset = q.vma_offset;
				info.protection = 0;
				if (q.vma_flags & PROCMAP_QUERY_VMA_READABLE) info.protection |= PROT_READ;
				if (q.vma_flags & PROCMAP_QUERY_VMA_WRITABLE) info.protection |= PROT_WRITE;
				if (q.vma_flags & PROCMAP_QUERY_VMA_EXECUTABLE) info.protection |= PROT_EXEC;
				info.shared = (q.vma_flags & PROCMAP_QUERY_VMA_SHARED) != 0;
				info.inode = q.inode;
				info.anonShared = info.shared && q.vma_name_size > 0 && strncmp(name, "/dev/zero", 9) == 0;
				return info;
			}
			if (errno == ENOTTY || errno == EINVAL) {
				noQuery = true;
			} else if (errno == ENOENT) {
				close(fd);
				processLog.warning() << *this << ": Address 0x" << std::hex << address << " not found in \"/proc/" << std::dec << _pid << "/maps\"" << processLog.endLog;
				throw std::system_error(EFAULT, std::generic_category());
			}
		}
	}

	// read in chunks; a line split across two reads is carried over
	std::vector<char> buf(256 * 1024);
	size_t have = 0;
	bool eof = false;
	bool found = false;

	while (!found) {
		if (!eof) {
			ssize_t n = read(fd, buf.data() + have, buf.size() - have);
			if (n < 0) {
				if (errno == EINTR) continue;
				break;
			}
			if (n == 0) eof = true;
			have += n;
		}
		const char* p = buf.data();
		const char* end = p + have;
		const char* lineEnd;
		while (p < end && ((lineEnd = (const char*)memchr(p, '\n', end - p)) || eof)) {
			if (!lineEnd) lineEnd = end;
			const char* q = p;
			uintptr_t start, stop;
			if (!parseHex(q, lineEnd, start) || q >= lineEnd || *q++ != '-' || !parseHex(q, lineEnd, stop)) {
				processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			} else if (stop > address && start <= address) {
				skipSpaces(q, lineEnd);
				const char* perms = q;
				q = skipField(q, lineEnd);
				std::string_view permsView(perms, q - perms);
				skipSpaces(q, lineEnd);
				uintptr_t offset = 0;
				parseHex(q, lineEnd, offset);
				skipSpaces(q, lineEnd);
				q = skipField(q, lineEnd);   // device
				skipSpaces(q, lineEnd);
				uint64_t inode = 0;
				while (q < lineEnd && *q >= '0' && *q <= '9') inode = inode * 10 + (*q++ - '0');
				skipSpaces(q, lineEnd);
				std::string_view pathView(q, lineEnd - q);

				info.startAddress = start;
				info.pageCount = (stop - start) / sysconf(_SC_PAGESIZE);
				info.mapOffset = offset;
				info.protection = 0;
				if (permsView.find('r') != std::string_view::npos) info.protection |= PROT_READ;
				if (permsView.find('w') != std::string_view::npos) info.protection |= PROT_WRITE;
				if (permsView.find('x') != std::string_view::npos) info.protection |= PROT_EXEC;
				info.shared = permsView.find('s') != std::string_view::npos;
				info.inode = inode;
				// x86Sim: shared anonymous memory is a shmem object Linux names "/dev/zero (deleted)"
				info.anonShared = info.shared && pathView.rfind("/dev/zero", 0) == 0;
				found = true;
				break;
			}
			p = lineEnd < end ? lineEnd + 1 : end;
		}
		if (found || eof) break;
		// keep the partial line
		have = end - p;
		memmove(buf.data(), p, have);
		if (have == buf.size()) buf.resize(buf.size() * 2);
	}
	close(fd);

	if (found) {
		return info;
	}

	processLog.warning() << *this << ": Address 0x" << std::hex << address << " not found in \"/proc/" << std::dec << _pid << "/maps\"" << processLog.endLog;
	throw std::system_error(EFAULT, std::generic_category());
};

#if DSERVER_EXTENDED_DEBUG

void DarlingServer::Process::_registerName(uint32_t name, uintptr_t pointer) {
	std::unique_lock lock(_rwlock);
	_registeredNames[name] = pointer;
};

void DarlingServer::Process::_unregisterName(uint32_t name) {
	std::unique_lock lock(_rwlock);
	_registeredNames.erase(name);
};

void DarlingServer::Process::_addPortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID) {
	std::unique_lock lock(_rwlock);
	auto& members = _portSetMembers[portSetID];
	members.insert(portID);
};

void DarlingServer::Process::_removePortSetMember(dtape_port_set_id_t portSetID, dtape_port_id_t portID) {
	std::unique_lock lock(_rwlock);
	if (_portSetMembers.find(portSetID) != _portSetMembers.end()) {
		auto& members = _portSetMembers[portSetID];
		members.erase(portID);
		if (members.empty()) {
			_portSetMembers.erase(portSetID);
		}
	}
};

void DarlingServer::Process::_clearPortSet(dtape_port_set_id_t portSetID) {
	std::unique_lock lock(_rwlock);
	_portSetMembers.erase(portSetID);
};

#endif

std::shared_ptr<DarlingServer::Process> DarlingServer::Process::tracerProcess() const {
	std::shared_lock lock(_rwlock);
	return _tracerProcess.lock();
};

bool DarlingServer::Process::setTracerProcess(std::shared_ptr<Process> tracerProcess) {
	std::unique_lock lock(_rwlock);
	if (!_tracerProcess.expired()) {
		return false;
	}
	_tracerProcess = tracerProcess;
	return true;
};

std::shared_ptr<DarlingServer::Thread> DarlingServer::Process::_pickS2CThread(void) const {
	if (isDead()) {
		return nullptr;
	}

	// if we're the process for the current thread (i.e. we're the current process), use the current thread, unless
	// it's dying (x86Sim, willi/darlingserver#14)
	if (currentProcess().get() == this) {
		auto current = Thread::currentThread();
		if (current && !current->isDead()) {
			return current;
		}
	}

	// otherwise, pick any thread that isn't dead (a dead one would never take it). x86Sim (willi/darlingserver#14): the
	// weak references are copied under the lock and locked outside it, as notifyDead() does: the last reference to a
	// dying thread may be the one taken here, and ~Thread takes this lock.
	std::vector<std::weak_ptr<Thread>> candidates;
	{
		std::shared_lock lock(_rwlock);
		candidates.reserve(_threads.size());
		for (auto& [id, weakThread]: _threads) {
			candidates.push_back(weakThread);
		}
	}
	for (auto& weakThread: candidates) {
		if (auto thread = weakThread.lock(); thread && !thread->isDead()) {
			return thread;
		}
	}
	return nullptr;
};

std::string DarlingServer::Process::executablePath() const {
	std::shared_lock lock(_rwlock);
	return _executablePath;
};

void DarlingServer::Process::setExecutablePath(std::string path) {
	std::unique_lock lock(_rwlock);
	_executablePath = std::move(path);
};

// x86Sim (willi/darlingserver#14): runs `function` with a thread of ours to perform the S2C call. One that dies before
// it takes the call fails it with ESRCH, unsent, and another thread is picked (_pickS2CThread() skips the dead), 16
// tries at most. As XNU's vm_map_enter() into another task doesn't depend on which of its threads runs.
template<typename Function>
auto DarlingServer::Process::_performS2C(Function&& function) {
	for (int attempt = 1; ; attempt++) {
		auto thread = _pickS2CThread();
		if (!thread) {
			throw std::system_error(ESRCH, std::generic_category());
		}
		try {
			return function(thread);
		} catch (const std::system_error& e) {
			if (e.code().value() != ESRCH || !thread->isDead() || attempt >= 16) {
				throw;
			}
		}
	}
};

uintptr_t DarlingServer::Process::allocatePages(size_t pageCount, int protection, uintptr_t addressHint, bool fixed, bool overwrite) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->allocatePages(pageCount, protection, addressHint, fixed, overwrite);
	});
};

void DarlingServer::Process::freePages(uintptr_t address, size_t pageCount) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->freePages(address, pageCount);
	});
};

uintptr_t DarlingServer::Process::mapFile(int fd, size_t pageCount, int protection, uintptr_t addressHint, size_t pageOffset, bool fixed, bool overwrite, bool priv) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->mapFile(fd, pageCount, protection, addressHint, pageOffset, fixed, overwrite, priv);
	});
};

void DarlingServer::Process::changeProtection(uintptr_t address, size_t pageCount, int protection) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->changeProtection(address, pageCount, protection);
	});
};

void DarlingServer::Process::syncMemory(uintptr_t address, size_t size, int sync_flags) {
	return _performS2C([&](const std::shared_ptr<Thread>& thread) {
		return thread->syncMemory(address, size, sync_flags);
	});
};

static const std::regex memoryRegionEntryAddressRegex("([0-9a-fA-F]+)\\-([0-9a-fA-F]+)");

uintptr_t DarlingServer::Process::getNextRegion(uintptr_t address) const {
	if (isDead()) {
		throw std::system_error(ESRCH, std::generic_category(), "dead process; can't call getNextRegion");
	}

	std::ifstream file("/proc/" + std::to_string(_pid) + "/maps");
	std::string line;

	while (std::getline(file, line)) {
		std::smatch match;

		if (!std::regex_search(line, match, memoryRegionEntryAddressRegex)) {
			processLog.warning() << "Encountered malformed `/proc/<pid>/maps` entry? Definitely a bug (on our part)." << processLog.endLog;
			continue;
		}

		auto startAddress = std::stoul(match[1].str(), nullptr, 16);
		auto endAddress = std::stoul(match[2].str(), nullptr, 16);

		if (startAddress <= address) {
			continue;
		}

		// /proc/<pid>/maps is sorted in ascending order, so as soon as we find a line with a starting address greater than `address`, that's the next region

		return startAddress;
	}

	return 0;
};

void DarlingServer::Process::notifyDead() {
	decltype(_threads) threads;
	{
		std::unique_lock lock(_rwlock);
		if (_dead) {
			return;
		}

		processLog.info() << *this << ": process dying" << processLog.endLog;
		_dead = true;
		threads = _threads;

		// clear out all kqchannels we own
		_kqchannels.clear();
	}

	// keep ourselves alive until the duct-taped context is done
	_selfReference = shared_from_this();

	// TODO: get exit status
	_notifyListeningKqchannels(NOTE_EXIT, 0);

	// notify all our threads that we're dead
	for (auto [id, maybeThread]: threads) {
		auto thread = maybeThread.lock();
		if (!thread) {
			continue;
		}
		thread->notifyProcessDead(); // x86Sim (willi/darlingserver#10)
	}

	// schedule the duct-taped task to be released
	// dtape_thread_release needs a microthread context, so we call it within a kernel microthread
	// also destroy the fork-wait semaphore here
	Thread::kernelAsync([self = shared_from_this()]() {
		// x86Sim: (willi/darlingserver#3) its threads are dead: terminate the task's IPC now, as XNU does
		// (ipc_space_terminate can block, so this needs the microthread context)
		dtape_task_dying(self->_dtapeTask);

		dtape_semaphore_t* forkWaitSemaphore = nullptr;
		{
			std::unique_lock lock(self->_rwlock);
			forkWaitSemaphore = self->_dtapeForkWaitSemaphore;
			self->_dtapeForkWaitSemaphore = nullptr;
		}
		if (forkWaitSemaphore) {
			dtape_semaphore_destroy(forkWaitSemaphore);
		}
		dtape_task_release(self->_dtapeTask);
		self->_dtapeTask = nullptr;
	});

	processRegistry().unregisterEntry(shared_from_this());
};

void DarlingServer::Process::_dispose() {
	_selfReference = nullptr;
};

bool DarlingServer::Process::isDead() const {
	std::shared_lock lock(_rwlock);
	return _dead;
};

std::vector<uint32_t> DarlingServer::Process::groups() const {
	std::shared_lock lock(_rwlock);
	return _groups;
};

void DarlingServer::Process::setGroups(const std::vector<uint32_t>& groups) {
	std::unique_lock lock(_rwlock);
	_groups = groups;
};
