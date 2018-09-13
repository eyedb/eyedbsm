/* 
   EyeDB Object Database Management System
   Copyright (C) 1994-2008 SYSRA
   
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


#ifndef _EYEDBLIB_PERFORMER_H
#define _EYEDBLIB_PERFORMER_H

#include <eyedblib/thread.h>

namespace eyedblib {
  struct ThreadPerformerArg {
    ThreadPerformerArg(void *_data, unsigned int _size = 0) {
      data = _data;
      size = _size;
#ifdef SPARCV9
      pad = 0;
#endif
    }

    operator void*() {return data;}
    void *data;
    int size;
#ifdef SPARCV9
    int pad;
#endif
  };

  typedef ThreadPerformerArg (*ThreadPerformerFunction)(ThreadPerformerArg);

  class ThreadPerformer {

  public:
    ThreadPerformer(void (*init)(ThreadPerformer *, void *) = 0,
		    void *init_arg = 0);
    void start(Thread *, ThreadPerformerFunction exec,
	       ThreadPerformerArg arg = 0);
    ThreadPerformerArg wait();
    Thread *getThread() {return thr;}
    bool isIdle() const {return !thr || thr->isIdle();}

    void *getUserData() {return user_data;}
    void *setUserData(void *);

    ~ThreadPerformer();

  private:
    void *return_arg;
    void *user_data;
    friend class ThreadPool;
    static void *thread_wrapper(void *);
    void resume(Thread *);
    Thread *thr;
    struct WrapperArg {
      ThreadPerformerFunction exec;
      void *input_arg;
    } wrap_arg;
    ThreadPerformer *wait_prev, *wait_next;
    ThreadPerformer *run_prev, *run_next;
    bool free;
  };

  class ThreadPool {

  public:
    ThreadPool(unsigned int thread_cnt);
    ThreadPool(void (*init)(ThreadPerformer *, void *), void *init_arg,
	       unsigned int thread_cnt);

    void reset();
    ThreadPerformer *start(ThreadPerformerFunction exec,
			   ThreadPerformerArg arg = 0);
    ThreadPerformerArg wait(ThreadPerformer *&);

    ThreadPerformer *getOne();

    Thread::Profile **getProfiles(unsigned int &cnt) const;
    void setProfile(bool);
    bool isProfiled() const {return profiled;}
    void profileReset();

    void release(ThreadPerformer *);
    void waitAll();

    unsigned int getThreadCount() const {return thread_cnt;}
    unsigned int getCurrentThreadPerformerCount() const {return current_thread_performer_cnt;}

    ~ThreadPool();

    void print(FILE *fd = stdout); // for debug

  private:
    bool profiled;
    ThreadPerformer *getOneRealize();
    unsigned int thread_cnt;
    unsigned int current_thread_performer_cnt;
    void init(unsigned int thread_cnt);
    void (*init_performer)(ThreadPerformer *, void *);
    void *init_performer_arg;
    eyedblib::Mutex mut;
    ThreadPerformer **performers;
    Thread **thrs;
    Condition *end_cond;
    static void endExecWrapper(Thread *thr, void *);
    ThreadPerformer *wait_first;
    ThreadPerformer *run_first;
    void addToWaitQueue(ThreadPerformer *perf);
    ThreadPerformer *peekFromWaitQueue();
    void addToRunQueue(ThreadPerformer *perf);
    ThreadPerformer *peekFromRunQueue();
    Thread *getOneThread();
    void beforeStart(ThreadPerformer *perf, Thread *thr);
  };

  std::ostream &operator<<(std::ostream &, Thread::Profile **);

}

#endif
