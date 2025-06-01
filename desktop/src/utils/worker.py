#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import time
from typing import (
    Optional, Tuple, Dict, Any
)
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import (
    QTimer, QRunnable, Slot, Signal, QObject, QThreadPool
)


class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.
    
    Supported signals are:
    - interval_finished: Signal emitted when the interval function completes.
    - interval_output: Signal emitted for interval output.
    - interval_error: Signal emitted on an interval error.
    """
    interval_finished = Signal(object)
    interval_output = Signal(object)
    interval_error = Signal(object)


class Worker(QRunnable):
    """
    Worker thread for running a function at specified intervals.

    :param function: The function to be executed.
    :type function: callable
    :param interval: The interval in seconds between function executions.
    :type interval: int, optional
    :param args: Additional positional arguments to pass to the function.
    :param kwargs: Additional keyword arguments to pass to the function.
    """

    def __init__(self, function: callable, interval: Optional[int] = None, *args, **kwargs) -> None:
        """
        Initialize the worker with a function and interval.

        :param function: The function to be executed.
        :type function: callable
        :param interval: The interval in seconds between function executions.
        :type interval: int, optional
        :param args: Additional positional arguments to pass to the function.
        :param kwargs: Additional keyword arguments to pass to the function.
        """
        super(Worker, self).__init__()

        self.function: callable = function
        self.interval: Optional[int] = interval
        self.args: Tuple = args
        self.kwargs: Dict = kwargs
        self.signals: WorkerSignals = WorkerSignals()
        self.alive: bool = True 
        self.suspended: bool = False
        self.remaining: float = 0
        self.checkpoint_interval: float = 0.1

        QApplication.instance().aboutToQuit.connect(self.abort)

    @Slot()
    def run(self) -> None:
        """
        The main entry point for the worker thread.
        """
        while self.alive:
            if self.remaining <= 0:
                try: 
                    result: Any = self.function(*self.args, **self.kwargs)
                    if self.alive:
                        self.signals.interval_finished.emit(result)
                except Exception as e:
                    if self.alive:
                        self.signals.interval_error.emit(e)
                if self.interval is None:
                    break
                self.remaining = self.interval

            time.sleep(self.checkpoint_interval)
            if not self.suspended:
                self.remaining -= self.checkpoint_interval

    def abort(self) -> None:
        """
        Abort the worker thread.
        """
        self.alive = False

    def pause(self) -> None:
        """
        Pause the worker thread.
        """
        self.suspended = True

    def resume(self) -> None:
        """
        Resume the worker thread.
        """
        self.suspended = False

    def invoke_run(self) -> None:
        """
        Immediately invoke the function in the worker thread.
        """
        self.remaining = 0
