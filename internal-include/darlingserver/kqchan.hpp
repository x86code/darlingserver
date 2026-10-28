#ifndef _DARLINGSERVER_KQCHAN_HPP_
#define _DARLINGSERVER_KQCHAN_HPP_

#include <memory>
#include <optional>
#include <deque>

#include <darlingserver/monitor.hpp>
#include <darlingserver/message.hpp>
#include <darlingserver/duct-tape.h>
#include <darlingserver/logging.hpp>

#define NOTE_EXIT        0x80000000U
#define NOTE_FORK        0x40000000U
#define NOTE_EXEC        0x20000000U
#define NOTE_REAP        0x10000000U
#define NOTE_SIGNAL      0x08000000U
#define NOTE_EXITSTATUS  0x04000000U
#define NOTE_EXIT_DETAIL 0x02000000U
#define NOTE_TRACK       0x00000001U
#define NOTE_TRACKERR    0x00000002U
#define NOTE_CHILD       0x00000004U
#define NOTE_PDATAMASK   0x000fffffU
#define NOTE_PCTRLMASK  (~(NOTE_PDATAMASK))

namespace DarlingServer {
	class Process;
	class Thread;

	class Kqchan: public Loggable {
		friend class DarlingServer::Process;

	protected:
		uint64_t _debugID;
		std::weak_ptr<DarlingServer::Process> _process;
		std::shared_ptr<FD> _socket;
		std::shared_ptr<Monitor> _monitor;
		MessageQueue _inbox;
		MessageQueue _outbox;
		bool _canSend = false;
		std::mutex _notificationMutex;
		bool _canSendNotification = true;
		bool _deferNotification = false;
		std::optional<Message> _deferredNotification = std::nullopt;
		std::mutex _sendingMutex;
		uint64_t _notificationCount = 0;

		Kqchan(std::shared_ptr<DarlingServer::Process> process);

		virtual uintptr_t _idForProcess() const;

		virtual void _processMessages();

		virtual std::shared_ptr<Kqchan> sharedFromRoot();

		void _sendNotification();
		void _sendDeferredNotification();

	public:
		virtual ~Kqchan();

		virtual int setup();

		void logToStream(Log::Stream& stream) const;

		class MachPort;
		class Process;
	};


	/**
	 * A Mach port knote of a process's kqueue, served over a socket pair with libkqueue's machport filter
	 * (src/external/libkqueue/src/linux/machport.c), which must match it.
	 *
	 * - notification: sent (at most one outstanding) when the port has a message; the peer's epoll sees the socket
	 *   readable. A read or a modify lets the next one be sent.
	 * - read: the peer reads the notification, then sends a read request and gets the event as the reply. By the time
	 *   it reads, another thread of the peer may have consumed the notification; it then drops the event rather than
	 *   wait, and the next notification brings it.
	 * - modify: the peer sends the new receive buffer and flags and waits for the reply. A notification sent before
	 *   the request arrives ahead of the reply, and the peer skips it; so with the reply we check for events again and
	 *   send a new notification after the reply (`_deferNotification`) if the port still has a message.
	 */
	class Kqchan::MachPort: public Kqchan, public std::enable_shared_from_this<MachPort> {
	private:
		uint32_t _port;
		uint64_t _receiveBuffer;
		uint64_t _receiveBufferSize;
		uint64_t _savedFilterFlags;
		dtape_kqchan_mach_port_t* _dtapeKqchan = nullptr;
		// the duct-taped kqchan's notification context: a notifier can still be running when we're destroyed, so it
		// gets a weak reference to us, freed once the duct-taped kqchan is gone
		std::weak_ptr<MachPort>* _notifyContext = nullptr;

		void _modify(uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags, pid_t nstid);
		void _read(uint64_t defaultBuffer, uint64_t defaultBufferSize, pid_t nstid);

		void _notify();

		virtual void _processMessages();

		/**
		 * This method is used to check for events in an async, lock-safe manner.
		 * This is because the caller may be holding a lock on the kqchan or may even be outside a microthread,
		 * so the actual check needs to be scheduled in a kernel microthread.
		 */
		void _checkForEventsAsync();
		std::function<void()> _checkForEventsAsyncFactory();

	protected:
		virtual uintptr_t _idForProcess() const;

		virtual std::shared_ptr<Kqchan> sharedFromRoot();

	public:
		MachPort(std::shared_ptr<DarlingServer::Process> process, uint32_t port, uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags);
		~MachPort();

		MachPort(const MachPort&) = delete;
		MachPort& operator=(const MachPort&) = delete;

		MachPort(MachPort&&) = delete;
		MachPort& operator=(MachPort&&) = delete;

		virtual int setup();
	};

	class Kqchan::Process: public Kqchan, public std::enable_shared_from_this<Process> {
		friend class DarlingServer::Process;

	private:
		// some events can be coalesced, but ones like NOTE_FORK and NOTE_EXIT can't be sent in a single event
		struct Event {
		public:
			uint32_t events;
			int64_t data;
			std::shared_ptr<Process> newKqchan;
		};

		pid_t _nspid;
		uint32_t _flags;
		std::mutex _mutex;
		std::deque<Event> _events;
		std::weak_ptr<DarlingServer::Process> _targetProcess;
		bool _attached = false;

		void _modify(uint32_t flags);
		void _read();

		void _notify(uint32_t event, int64_t data);

		virtual void _processMessages();

		/**
		 * See Kqchan::MachPort::_checkForEventsAsync(); this does the same thing for process kqchannels.
		 */
		void _checkForEventsAsync();
		std::function<void()> _checkForEventsAsyncFactory();

	protected:
		virtual uintptr_t _idForProcess() const;

		virtual std::shared_ptr<Kqchan> sharedFromRoot();

	public:
		Process(std::shared_ptr<DarlingServer::Process> process, pid_t nspid, uint32_t flags);
		~Process();

		Process(const Process&) = delete;
		Process& operator=(const Process&) = delete;

		Process(Process&&) = delete;
		Process& operator=(Process&&) = delete;

		virtual int setup();

		virtual void logToStream(Log::Stream& stream) const;
	};
};

#endif // _DARLINGSERVER_KQCHAN_HPP_
