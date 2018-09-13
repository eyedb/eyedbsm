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

#include "eyedbsmconfig.h"

#include <iostream>
#include <streambuf>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <iomanip>

#include <eyedblib/performer.h>

using namespace std;

//#define TRACE

//
// ThreadPerformer methods
//

namespace eyedblib {

  void *
  ThreadPerformer::thread_wrapper(void *xarg)
  {
    WrapperArg *arg = (WrapperArg *)xarg;
    return arg->exec(arg->input_arg);
  }

  ThreadPerformer::ThreadPerformer(void (*init)(ThreadPerformer *, void *),
				   void *init_arg)
  {
    //thr = new Thread();
    thr = 0;
    user_data = 0;
    wait_prev = wait_next = 0;
    run_prev = run_next = 0;
    free = true;
    if (init)
      init(this, init_arg);
  }

  void
  ThreadPerformer::start(Thread *_thr, ThreadPerformerFunction exec, ThreadPerformerArg input_arg)
  {
    thr = _thr;
    wrap_arg.exec = exec;
    wrap_arg.input_arg = input_arg;
    if (thr)
      thr->execute(thread_wrapper, &wrap_arg);
  }

  void
  ThreadPerformer::resume(Thread *_thr)
  {
    thr = _thr;
    thr->execute(thread_wrapper, &wrap_arg);
  }

  ThreadPerformerArg
  ThreadPerformer::wait()
  {
    void *x = thr->wait();
    return x;
  }

  void *
  ThreadPerformer::setUserData(void *_user_data)
  {
    void *o_user_data = user_data;
    user_data = _user_data;
    return o_user_data;
  }

  ThreadPerformer::~ThreadPerformer()
  {
    delete thr;
  }

  //
  // ThreadPool definitions and methods
  //

  ThreadPool::ThreadPool(void (*init_p)(ThreadPerformer *, void *),
			 void *init_p_arg,
			 unsigned int _thread_cnt)
  {
    init_performer = init_p;
    init_performer_arg = init_p_arg;
    init(_thread_cnt);
  }

  ThreadPool::ThreadPool(unsigned int _thread_cnt)
  {
    init_performer = 0;
    init_performer_arg = 0;
    init(_thread_cnt);
  }

  void
  ThreadPool::init(unsigned int _thread_cnt)
  {
    profiled = false;
    thread_cnt = _thread_cnt;
    current_thread_performer_cnt = 0;
    thrs = new Thread*[thread_cnt];
    for (int n = 0; n < thread_cnt; n++)
      thrs[n] = new Thread();

    end_cond = new Condition();
    performers = 0;
    wait_first = run_first = 0;
  }

  void
  ThreadPool::endExecWrapper(Thread *thr, void *xthrpool)
  {
    ThreadPool *thrpool = (ThreadPool *)xthrpool;
#ifdef TRACE
    printf("#%d endExecWrapper\n", pthread_self());
#endif
    ThreadPerformer *p = (ThreadPerformer *)thr->getUserData();
    p->return_arg = thr->wait();
    p->thr = 0;
    thrpool->release(p);

    p = thrpool->peekFromWaitQueue();
    if (p) {
      thrpool->beforeStart(p, thr);
      p->resume(thr);
    }

    thrpool->end_cond->signal();
  }

  void
  ThreadPool::beforeStart(ThreadPerformer *p, Thread *thr)
  {
    p->return_arg = 0;
    thr->onEndExec(endExecWrapper, this);
    thr->setUserData(p);
    addToRunQueue(p);
  }

  Thread *
  ThreadPool::getOneThread()
  {
    for (int n = 0; n < thread_cnt; n++)
      if (thrs[n]->isIdle())
	return thrs[n];
    return 0;
  }

  void
  ThreadPool::addToWaitQueue(ThreadPerformer *p)
  {
    MutexLocker _(mut);

    p->wait_next = wait_first;
    if (wait_first)
      wait_first->wait_prev = p;

    wait_first = p;
    p->wait_prev = 0;
  }

  ThreadPerformer *
  ThreadPool::peekFromWaitQueue()
  {
    MutexLocker _(mut);
    if (!wait_first)
      return 0;
    ThreadPerformer *p = wait_first;
    if (p->wait_next)
      p->wait_next->wait_prev = 0;
    wait_first = p->wait_next;
    p->wait_next = 0;
    return p;
  }

  void
  ThreadPool::addToRunQueue(ThreadPerformer *p)
  {
    MutexLocker _(mut);

    ThreadPerformer *pp = run_first;
    while (pp) {
      if (p == pp) {
	return;
      }
      pp = pp->run_next;
    }

    p->run_next = run_first;
    if (run_first)
      run_first->run_prev = p;

    run_first = p;
    p->run_prev = 0;
  }

  ThreadPerformer *
  ThreadPool::peekFromRunQueue()
  {
    MutexLocker _(mut);
    if (!run_first)
      return 0;
    ThreadPerformer *p = run_first;
    while (p) {
      if (p->free) {
	if (p->run_next)
	  p->run_next->run_prev = p->run_prev;
	if (p->run_prev)
	  p->run_prev->run_next = p->run_next;
	if (p == run_first)
	  run_first = p->run_next;
	p->run_next = p->run_prev = 0;
	return p;
      }
      p = p->run_next;
    }

    return 0;
  }

  ThreadPerformer *
  ThreadPool::start(ThreadPerformerFunction exec, ThreadPerformerArg arg)
  {
    ThreadPerformer *performer = getOne();
#ifdef TRACE
    printf("ThreadPool: getting %p\n", performer);
#endif
    if (performer) {
      Thread *thr = getOneThread();
#ifdef TRACE
      printf("Getting thread %p\n", thr);
      if (thr)
	printf(" -> thread @%d:%d\n",
	       thr->get_thread(),
	       thr->get_pid());
#endif
      if (thr)
	beforeStart(performer, thr);
      else
	addToWaitQueue(performer);

      performer->start(thr, exec, arg);
    }
    return performer;
  }

  ThreadPerformerArg
  ThreadPool::wait(ThreadPerformer *&p)
  {
    end_cond->wait();
    p = peekFromRunQueue();
    if (p) return p->return_arg;
    return 0;
  }

  void
  ThreadPool::reset()
  {
    waitAll();
    while (peekFromRunQueue())
      ;
    end_cond->reset();
  }

  void
  ThreadPool::print(FILE *fd)
  {
    fprintf(fd, "%d Threads\n", thread_cnt);
    int busy_cnt = 0, free_cnt = 0;
    for (int i = 0; i < current_thread_performer_cnt; i++) {
      if (performers[i]->free)
	free_cnt++;
      else
	busy_cnt++;
    }

    fprintf(fd, "%d Thread Performers\n", current_thread_performer_cnt);
    fprintf(fd, "%d Free Thread Performers\n", free_cnt);
    fprintf(fd, "%d Busy Thread Performers\n", busy_cnt);
    ThreadPerformer *p = wait_first;
    int wait_cnt = 0;
    while (p) {
      wait_cnt++;
      p = p->wait_next;
    }
    fprintf(fd, "%d Thread Performers in wait queue\n", wait_cnt);
    p = run_first;
    int run_cnt = 0;
    while (p) {
      run_cnt++;
      p = p->run_next;
    }
    fprintf(fd, "%d Thread Performers in run queue\n", run_cnt);
  }

  void
  ThreadPool::waitAll()
  {
    /*
      for (int i = 0; i < current_thread_performer_cnt; i++) {
      if (!performers[i]->free)
      (void)wait(performers[i]);
      }
    */
    while (run_first) {
      ThreadPerformer *perf;
      wait(perf);
    }
  }

  void
  ThreadPool::setProfile(bool _profiled)
  {
    profiled = true;
    unsigned int cnt = thread_cnt;
    if (current_thread_performer_cnt < cnt)
      cnt = current_thread_performer_cnt;

    for (int i = 0; i < cnt; i++) {
      ThreadPerformer *thrperf = performers[i];
      thrperf->getThread()->setProfile(profiled);
    }
  }

  void
  ThreadPool::profileReset()
  {
    unsigned int cnt = thread_cnt;
    if (current_thread_performer_cnt < cnt)
      cnt = current_thread_performer_cnt;

    for (int i = 0; i < cnt; i++) {
      ThreadPerformer *thrperf = performers[i];
      thrperf->getThread()->resetProfile();
    }
  }

  Thread::Profile **
  ThreadPool::getProfiles(unsigned int &cnt) const
  {
    cnt = thread_cnt;
    if (current_thread_performer_cnt < cnt)
      cnt = current_thread_performer_cnt;
  
    Thread::Profile **profiles = new Thread::Profile*[cnt+1];
    for (int i = 0; i < cnt; i++) {
      ThreadPerformer *thrperf = performers[i];
      profiles[i] = new Thread::Profile(thrperf->getThread());
      *profiles[i] = thrperf->getThread()->getProfile();
    }

    profiles[cnt] = 0;
    return profiles;
  }

  void ProfileStats::display_time(ostream &os, double usec)
  {
    char buf[512];
    bool prev = false;
    if (usec < 1000) {
      sprintf(buf, "%.2f", usec);
      os << buf << "us";
      prev = true;
    }

    usec /= 1000;
    if (usec >= 0.01) {
      if (usec < 1000) {
	sprintf(buf, "%s%.2f", (prev ? " " : ""), usec);
	os << buf << "ms";
	prev = true;
      }
      usec /= 1000;
      if (usec >= 0.01) {
	sprintf(buf, "%s%.2f", (prev ? " " : ""), usec);
	os << buf << "s";
      }
    }
  }

  ostream &operator<<(ostream &os, Thread::Profile **profiles)
  {
    int n = 0;
    unsigned long long run_cnt = 0;
    unsigned long long wait_usec = 0;
    unsigned long long run_usec = 0;
    double run_avg_usec = 0.;
    double wait_avg_usec = 0.;
    for (; profiles[n]; n++) {
      run_cnt += profiles[n]->run_cnt;
      wait_usec += profiles[n]->wait.usec;
      run_usec += profiles[n]->run.usec;
      os << *profiles[n];
    }

    os << "\nTotal threads:             " << n << "\n";
    os << "Total runs:                " << run_cnt << "\n";
    os << "Total run time:            ";
    ProfileStats::display_time(os, run_usec);
    os << "\nTotal wait time:           ";
    ProfileStats::display_time(os, wait_usec);
    os << "\nAverage total run/thread:  ";
    ProfileStats::display_time(os, (double)run_usec/n);
    os << "\nAverage one run/thread:    ";
    ProfileStats::display_time(os, (double)run_usec/run_cnt);
    os << "\nAverage total wait/thread: ";
    ProfileStats::display_time(os, (double)wait_usec/n);
    os << "\nAverage one wait/thread:   ";
    ProfileStats::display_time(os, (double)wait_usec/run_cnt);
    os << endl;
    return os;
  }

  ThreadPerformer *
  ThreadPool::getOne()
  {
    MutexLocker locker(mut);
    return getOneRealize();
  }

  ThreadPerformer *
  ThreadPool::getOneRealize()
  {
    for (int i = 0; i < current_thread_performer_cnt; i++) {
      ThreadPerformer *p = performers[i];
      if (p->free) {
	p->free = false;
	p->run_next = p->run_prev = p->wait_next = p->wait_prev = 0;
	return p;
      }
    }

    int o_current_thread_performer_cnt = current_thread_performer_cnt;

    current_thread_performer_cnt += 8;

    performers = (ThreadPerformer **)realloc(performers,
					     sizeof(ThreadPerformer *) *
					     current_thread_performer_cnt);

    for (int i = o_current_thread_performer_cnt; i < current_thread_performer_cnt; i++) {
      performers[i] = new ThreadPerformer(init_performer, init_performer_arg);
      //performers[i]->performer->getThread()->setProfile(profiled);
    }

    return getOneRealize();
  }

  void
  ThreadPool::release(ThreadPerformer *performer)
  {
    MutexLocker _(mut);
    assert(!performer->free);
#ifdef TRACE
    printf("#%d setting free -> %p\n", pthread_self(), performer);
#endif
    performer->free = true;
  }

  ThreadPool::~ThreadPool()
  {
    for (int i = 0; i < current_thread_performer_cnt; i++)
      delete performers[i];
    free(performers);
  }

}
