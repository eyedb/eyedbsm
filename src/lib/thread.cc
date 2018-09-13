/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2018 SYSRA
   
   EyeDB is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   
   EyeDB is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA 
*/

/*
   Author: Eric Viara <viara@sysra.com>
*/

#include <eyedbsmconfig.h>

#include <eyedblib/thread.h>
#include <eyedblib/rpc_lib.h>

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

using namespace std;

//#define TRACE

namespace eyedblib {

  pthread_key_t Thread::self_key;

  struct Thread::Initializer {
    Initializer() {
      assert(!pthread_key_create(&Thread::self_key, 0));
    }
  };

  static Thread::Initializer initializer;

  //
  // Mutex methods
  //

  Mutex::Mutex(Type _type, bool _lock)
  {
    type = _type;
    init(_lock);
  }

  Mutex::Mutex(bool _lock)
  {
    type = PROCESS_PRIVATE;
    init(_lock);
  }

  int Mutex::init(Type _type, bool _lock)
  {
    type = _type;
    return init(_lock);
  }

  int Mutex::init(bool _lock)
  {
    pthread_mutexattr_t mattr;
    int r = pthread_mutexattr_init(&mattr);
    if (r) return r;

#ifdef HAVE_PTHREAD_PROCESS_SHARED
    if (type == PROCESS_SHARED) {
      r = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
      if (r) return r;
    }
    else {
      r = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_PRIVATE);
      if (r) return r;
    }
#endif
    r = pthread_mutex_init(&mut, &mattr);
    if (r) return r;
  
    locked = false;
    if (_lock)
      lock();

    return pthread_mutexattr_destroy(&mattr);
  }

  int
  Mutex::lock()
  {
    int r = pthread_mutex_lock(&mut);
    locked = true;
    return r;
  }

  bool
  Mutex::trylock()
  {
    return !pthread_mutex_trylock(&mut);
  }

  int
  Mutex::unlock()
  {
#if 1
    if (!locked) {
      fprintf(stderr, "eyedblib::Mutex::unlock(): Assertion `locked' failed\n");
      fprintf(stderr, "dbgserv %d\n", rpc_getpid());
      fflush(stderr);
      sleep(1000);
      abort();
    }
#endif
    assert (locked);
    locked = false;
    return pthread_mutex_unlock(&mut);
  }

  Mutex::~Mutex()
  {
  }

  //
  // Condition methods
  //

  Condition::Condition(Type _type) : profile(this)
  {
    type = _type;
    init();
  }

  int
  Condition::init()
  {
    pthread_condattr_t cattr;
    int r = pthread_condattr_init(&cattr);
    if (r) return r;

#ifdef HAVE_PTHREAD_PROCESS_SHARED
    if (type == PROCESS_SHARED) {
      r = pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
      if (r) return r;
    }
    else {
      r = pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_PRIVATE);
      if (r) return r;
    }
#endif
    r = pthread_cond_init(&cnd, &cattr);
    if (r) return r;
    cond = 0;
    wait_cnt = 0;
    profiled = false;
    return 0;
  }

  int
  Condition::wait()
  {
    int r = mut.lock();
    if (r) return r;
    while (!cond) {
#ifdef TRACE
      Thread *thr = Thread::getCallingThread();
      if (thr)
	printf("Condition::wait(@%d:%d, %p) -> sleep\n", thr->get_thread(),
	       thr->get_pid(), this);
      else
	printf("Condition::wait(@%d, %p) -> sleep\n", pthread_self(), this);
#endif
      struct timeval tp_start_wait, tp_end_wait;
      if (profiled) {
	gettimeofday(&tp_start_wait, 0);
	profile.wait_cnt++;
      }
      wait_cnt++;
      r = pthread_cond_wait(&cnd, mut.forCondWait());
      if (r) {mut.unlock(); return r;}
      mut.condWakeup();
      if (profiled) {
	gettimeofday(&tp_end_wait, 0);
	profile.sigwakeup.set(tp_end_wait, profile.tpsig);
	profile.wait.set(tp_end_wait, tp_start_wait);
	profile.wakeup_cnt++;
      }
      --wait_cnt;
#ifdef TRACE
      if (thr)
	printf("Condition::wait(@%d:%d, %p) <- wakeup\n", thr->get_thread(),
	       thr->get_pid(), this);
      else
	printf("Condition::wait(@%d, %p) <- wakeup\n", pthread_self(), this);
#endif
    }
    --cond;
    assert(cond >= 0);
    return mut.unlock();
  }

#define USECS_PER_SEC 1000000

  bool
  Condition::timedWait(unsigned long usec)
  {
    bool ret = true;
    mut.lock();
    struct timespec tm;
    if (!cond) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      unsigned long sec = usec / USECS_PER_SEC;
      tm.tv_sec  = tv.tv_sec + sec;
      tm.tv_nsec = 1000 * (usec - sec * USECS_PER_SEC);
    }
    while (!cond) {
#ifdef TRACE
      Thread *thr = Thread::getCallingThread();
      if (thr)
	printf("Condition::timedwait(@%d:%d, %p) -> sleep\n", thr->get_thread(),
	       thr->get_pid(), this);
      else
	printf("Condition::timedwait(@%d, %p) -> sleep\n", pthread_self());
#endif
      wait_cnt++;
      int r = pthread_cond_timedwait(&cnd, mut.forCondWait(), &tm);
      mut.condWakeup();
      --wait_cnt;
#ifdef TRACE
      if (thr)
	printf("Condition::timedwait(@%d:%d, %p) <- wakeup\n", thr->get_thread(),
	       thr->get_pid(), this);
      else
	printf("Condition::timedwait(@%d, %p) <- wakeup\n", pthread_self(), this);
#endif
      if (r == ETIMEDOUT) {
	ret = false;
	break;
      }
      assert(!r);
    }
    if (ret)
      --cond;
    mut.unlock();
    return ret;
  }

  int
  Condition::signal()
  {
    int r = mut.lock();
    if (r) return r;
    cond++;
    if (wait_cnt) {
#ifdef TRACE
      Thread *thr = Thread::getCallingThread();
      if (thr)
	printf("Condition::signal(@%d:%d, %p)\n", thr->get_thread(),
	       thr->get_pid(), this);
      else
	printf("Condition::signal(@%d, %p)\n", pthread_self(), this);
#endif
      if (profiled) {
	gettimeofday(&profile.tpsig, 0);
	profile.signal_cnt++;
      }
      r = pthread_cond_signal(&cnd);
      if (r) return r;
    }
    return mut.unlock();
  }

  int
  Condition::reset()
  {
    int r = mut.lock();
    if (r) return r;

    if (wait_cnt)
      return -1;

    cond = 0;
    return mut.unlock();
  }

  void
  Condition::resetProfile()
  {
    profile.reset();
  }

  Condition::Profile::Profile(Condition *_cond)
  {
    cond = _cond;
    reset();
  }

  void
  Condition::Profile::reset()
  {
    wait_cnt = 0;
    wakeup_cnt = 0;
    signal_cnt = 0;
    tpsig.tv_sec = 0;
    tpsig.tv_usec = 0;
    nowait.reset();
    wait.reset();
  }

  Condition::~Condition()
  {
  }

  //
  // Thread methods
  //

  Thread::Thread(Type type, void (*_init)(Thread *, void *), void *_init_arg)
    : profile(this)
  {
    init_thr("", type, _init, _init_arg);
  }

  Thread::Thread(const char *_name, Type type,
		 void (*_init)(Thread *, void *), void *_init_arg)
    : profile(this)
  {
    init_thr(_name, type, _init, _init_arg);
  }

  void
  Thread::init_thr(const char *_name, Type type,
		   void (*_init)(Thread *, void *), void *_init_arg)
  {
    pthread_attr_t attr;
    start_exec = 0;
    start_exec_data = 0;
    end_exec = 0;
    end_exec_data = 0;
    init = _init;
    init_arg = _init_arg;
    profiled = false;
    name = strdup(_name);
    user_data = 0;
    assert (!pthread_attr_init(&attr));

    if (type == SCOPE_SYSTEM)
      assert (!pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM));
    else
      assert (!pthread_attr_setscope(&attr, PTHREAD_SCOPE_PROCESS));

    assert (!pthread_create(&tid, &attr, run, this));
    pid = rpc_getpid();
    idle = true;
  }

  Thread::Thread(const char *_name, bool) : profile(this)
  {
    user_data = 0;
    init = 0;
    init_arg = 0;
    pid = rpc_getpid();
    name = strdup(_name);
    profiled = false;
  }

  void
  Thread::resetProfile()
  {
    profile.reset();
  }

  Thread::Profile::Profile(Thread *_thr)
  {
    thr = _thr;
    reset();
  }

  void
  Thread::Profile::reset()
  {
    run_cnt = 0;
    run.reset();
    wait.reset();
  }

  //
  // ProfileStats methods
  //

  void
  ProfileStats::reset()
  {
    usec = 0;
    max_usec = 0;
    min_usec = ~0LL;
  }

  ProfileStats::ProfileStats()
  {
    reset();
  }

  void
  ProfileStats::set(struct timeval &tp1, struct timeval &tp0)
  {
    unsigned long long u = (tp1.tv_sec - tp0.tv_sec) * 1000000 +
      (tp1.tv_usec - tp0.tv_usec);
    usec += u;
    if (u < min_usec)
      min_usec = u;
    if (u > max_usec)
      max_usec = u;
  }


  void ProfileStats::display(ostream &os, unsigned int cnt) const
  {
    if (!cnt) {
      os << "     <nil>\n";
      return;
    }

    os << "     Total time: ";
    display_time(os, usec);
    os << "\n     Min time:  ";
    display_time(os, min_usec);
    os << "\n     Max time:  ";
    display_time(os, max_usec);
    os << "\n     Average:  ";
    display_time(os, (double)usec / cnt);
  
    os <<"\n";
  }


  ostream &operator<<(ostream &os, const Condition::Profile &profile)
  {
    os << "Condition " << profile.cond << " { \n";
    if (!profile.wait_cnt) {
      os << "  <nil>\n}\n";
      return os;
    }
    os << "  Wait count: " << profile.wait_cnt << "\n";
    os << "  Wakeup count: " << profile.wakeup_cnt << "\n";
    os << "  Signal count: " << profile.signal_cnt << "\n";
    os << "  Signal/Wakeup statistics:\n";
    profile.sigwakeup.display(os, profile.wakeup_cnt);
    os << "  Wait statistics:\n";
    profile.wait.display(os, profile.wait_cnt);
    /*
      os << "  No Wait statistics:\n";
      profile.nowait.display(os, profile.wait_cnt);
    */
    os << "}" << endl;
    return os;
  }

  ostream &operator<<(ostream &os, const Thread::Profile &profile)
  {
    os << "Thread @" << profile.thr->get_thread() << ":" << profile.thr->get_pid() <<
      " { \n";
    if (!profile.run_cnt) {
      os << "  <nil>\n}\n";
      return os;
    }
    if (profile.thr->getName() && *profile.thr->getName())
      os << "  Name: " << profile.thr->getName() << "\n";

    os << "  Run count: " << profile.run_cnt << "\n";
    os << "  Run statistics:\n";
    profile.run.display(os, profile.run_cnt);
    os << "  Wait statistics:\n";
    profile.wait.display(os, profile.run_cnt);
    os << profile.thr->sync.cnd_start.getProfile();
    os << profile.thr->sync.cnd_end.getProfile();
    os << "}" << endl;
    return os;
  }

  void* Thread::run(void* xthr)
  {
    Thread *thr = (Thread *)xthr;

    thr->tid = pthread_self();
    assert(!pthread_setspecific(self_key, thr));
    if (thr->init)
      thr->init(thr, thr->init_arg);

    struct timeval tp_start_wait, tp_start_run, tp_end_run;
#ifdef TRACE
    printf("Thread::run(starting @%d:%d)\n", thr->get_thread(), thr->get_pid());
#endif

    for (;;) {
#ifdef TRACE
      printf("Thread::run(waiting for condition @%d:%d)\n", thr->get_thread(), thr->get_pid());
#endif
      if (thr->profiled)
	gettimeofday(&tp_start_wait, 0);

      assert(!thr->sync.cnd_start.wait());
#ifdef TRACE
      printf("Thread::run(resuming @%d:%d -> %p)\n", thr->get_thread(),
	     thr->get_pid(),  thr->exec.fun);
#endif
      if (thr->profiled) {
	gettimeofday(&tp_start_run, 0);
	thr->profile.wait.set(tp_start_run, tp_start_wait);
	thr->profile.run_cnt++;
      }

      if (thr->exec.fun) {
	thr->exec.return_arg = thr->exec.fun(thr->exec.input_arg);
      }

      if (thr->profiled) {
	gettimeofday(&tp_end_run, 0);
	thr->profile.run.set(tp_end_run, tp_start_run);
      }

#ifdef TRACE
      printf("Thread::run(ending @%d:%d)\n", thr->get_thread(), thr->get_pid());
#endif
      thr->idle = true;
      assert(!thr->sync.cnd_end.signal());
      if (thr->end_exec)
	thr->end_exec(thr, thr->end_exec_data);
    }

    return (void *)0;
  }

  Thread *
  Thread::getCallingThread()
  {
    Thread *thr = (Thread *)pthread_getspecific(self_key);
    if (thr)
      assert(thr->get_thread() == pthread_self());
    return thr;
  }

  Thread *
  Thread::initCallingThread()
  {
    Thread *thr = getCallingThread();
    if (thr) return thr;
    thr = new Thread("#CallingThread", true);
    thr->tid = pthread_self();
    assert(!pthread_setspecific(self_key, thr));
    return thr;
  }

  void *
  Thread::setUserData(void *_user_data)
  {
    void *o_user_data = user_data;
    user_data = _user_data;
    return o_user_data;
  }

  void
  Thread::execute(void *(*fun)(void *), void *input_arg)
  {
    if (!idle) wait();

    exec.fun = fun;
    exec.input_arg = input_arg;
    idle = false;
#ifdef TRACE
    printf("Thread::execute(cond_signal @%d:%d)\n", tid, pid);
#endif
    if (start_exec)
      start_exec(this, start_exec_data);
    assert(!sync.cnd_end.reset());
    assert(!sync.cnd_start.signal());
#ifdef TRACE
    printf("Thread::execute(after cond_signal @%d:%d)\n", tid, pid);
#endif
  }

  void *
  Thread::wait()
  {
#ifdef TRACE
    printf("Thread::wait(@%d:%d)\n", tid, pid);
#endif
    assert(!sync.cnd_end.wait());
#ifdef TRACE
    printf("Thread::wait(after @%d:%d)\n", tid, pid);
#endif
    return exec.return_arg;
  }

  void
  Thread::join()
  {
    void *r;
    assert (!pthread_join(tid, &r));
  }

  Thread::~Thread()
  {
    free(name);
    // ??
    //pthread_exit((void *)0); // ??
  }

}

