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


#ifndef _EYEDBLIB_THREAD_H
#define _EYEDBLIB_THREAD_H

#include <pthread.h>
#include <sys/time.h>

#include <iostream>

#ifdef ULTRASOL7
#include <ostream>
#endif

namespace eyedblib {

  class Mutex {

  public:
    enum Type {
      PROCESS_PRIVATE,
      PROCESS_SHARED
    };
    Mutex(Mutex::Type type, bool lock = false);
    Mutex(bool lock = false);

    int init(Mutex::Type type, bool lock = false);
    int init(bool lock = false);

    int lock();
    int unlock();
    bool isLocked() const {return locked;}
    bool trylock();

    pthread_mutex_t *get_mutex() {return &mut;}

    ~Mutex();

  private:
    Type type;
    bool locked;
    pthread_mutex_t mut;
    pthread_mutex_t *forCondWait() {locked = false; return &mut;}
    void condWakeup() {locked = true;}
    friend class Condition;
  };

  struct ProfileStats {
    unsigned long long usec;
    unsigned long long min_usec, max_usec;
    ProfileStats();
    void set(struct timeval &, struct timeval &);
    void reset();
    static void display_time(std::ostream &os, double usec);
    void display(std::ostream &os, unsigned int run_cnt) const;
  };

  class Condition {

  public:
    enum Type {
      PROCESS_PRIVATE,
      PROCESS_SHARED
    };
    Condition(Condition::Type type = PROCESS_PRIVATE);

    int init();
    int signal();
    int wait();
    int reset();

    bool timedWait(unsigned long usec);

    pthread_cond_t *get_condition() {return &cnd;}

    bool isProfiled() const {return profiled;}
    void setProfile(bool _profiled) {profiled = _profiled;}
    void resetProfile();

    struct Profile {
      Condition *cond;
      unsigned int wait_cnt;
      unsigned int wakeup_cnt;
      unsigned int signal_cnt;
      struct timeval tpsig;
      ProfileStats sigwakeup, nowait, wait;
      Profile(Condition *cond);
      void reset();
    } profile;

    Condition::Profile getProfile() const {return profile;}
    ~Condition();

  private:
    Type type;
    unsigned int cond;
    unsigned int wait_cnt;
    bool profiled;
    Mutex mut;
    pthread_cond_t cnd;
  };

  class Thread {

  public:
    enum Type {
      SCOPE_PROCESS,
      SCOPE_SYSTEM
    };

    Thread(Thread::Type type = SCOPE_SYSTEM,
	   void (*init)(Thread *, void *) = 0, void *init_arg = 0);
    Thread(const char *name, Thread::Type type = SCOPE_SYSTEM,
	   void (*init)(Thread *, void *) = 0, void *init_arg = 0);
    void execute(void *(*fun)(void *), void *input_arg = 0);
    void *wait();
    void join();

    void onStartExec(void (*_start_exec)(Thread *, void *), void * data = 0) {
      start_exec = _start_exec;
      start_exec_data = data;
    }
    void onEndExec(void (*_end_exec)(Thread *, void *), void * data = 0) {
      end_exec = _end_exec;
      end_exec_data = data;
    }

    void *getUserData() {return user_data;}
    void *setUserData(void *);

    bool isProfiled() {return profiled;}

    void setProfile(bool _profiled) {
      profiled = _profiled;
      sync.cnd_start.setProfile(profiled);
      sync.cnd_end.setProfile(profiled);
    }

    void resetProfile();
    const char *getName() const {return name;}

    struct Profile {
      Thread *thr;
      unsigned int run_cnt;
      ProfileStats run, wait;
      Profile(Thread *);
      void reset();
    } profile;

    Thread::Profile getProfile() const {return profile;}
    pthread_t get_thread() {return tid;}
    int get_pid() {return pid;}
    bool isIdle() const {return idle;}

    static Thread *getCallingThread();
    static Thread *initCallingThread();

    ~Thread();

  private:
    bool idle;
    static pthread_key_t self_key;
    void (*init)(Thread *, void *);
    void *init_arg;
    char *name;
    static void *run(void *);
    struct {
      Condition cnd_start, cnd_end;
    } sync;
    struct Exec {
      void *input_arg, *return_arg;
      void *(*fun)(void *);
      Exec() {
	input_arg = 0;
	return_arg = 0;
	fun = 0;
      }
    } exec;

    void (*start_exec)(Thread *, void *);
    void *start_exec_data;
    void (*end_exec)(Thread *, void *);
    void *end_exec_data;

    bool profiled;
    void *user_data;
    pthread_t tid;
    int pid;
    Thread(const char *, bool);
    void init_thr(const char *_name, Type type,
		  void (*_init)(Thread *, void *), void *_init_arg);

  public:
    class Initializer;
    friend class Initializer;
    friend std::ostream &operator<<(std::ostream &, const Thread::Profile &);
  };

  std::ostream &operator<<(std::ostream &, const Condition::Profile &);
  std::ostream &operator<<(std::ostream &, const Thread::Profile &);

  class MutexLocker {

  public:
    MutexLocker(Mutex &_mut) : mut(_mut) {mut.lock(); locked = true;}
    void lock() {mut.lock(); locked = true;}
    void unlock() {locked = false; mut.unlock();}
    ~MutexLocker() {if (locked) mut.unlock();}

  private:
    Mutex &mut;
    bool locked;
  };
}

#endif
