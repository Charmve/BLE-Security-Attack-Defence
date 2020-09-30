from threading import Timer

global_timers = {}


def start_timeout(timer_name, seconds, callback):
    global global_timers
    disable_timeout(timer_name)
    timer = Timer(seconds, callback)
    timer.daemon = True
    timer.setName(timer_name)
    timer.start()
    global_timers[timer_name] = timer


def update_timeout(timer_name):
    global global_timers
    if timer_name in global_timers:
        timer = global_timers[timer_name]

        if timer:
            timer.cancel()
            start_timeout(timer_name, timer.interval, timer.function)


def disable_timeout(timer_name):
    if timer_name in global_timers:
        timer = global_timers[timer_name]
        if timer:
            timer.cancel()
            timer.cancel()
            global_timers[timer_name] = None
