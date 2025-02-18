type TimerCallback = () => Promise<void> | void
type TimerId = string

interface Timer {
  id: TimerId
  interval: number
  callback: TimerCallback
  lastRun: number | null
  isRunning: boolean
}

class TimerService {
  private timers: Map<TimerId, Timer> = new Map()
  private intervalId: number | null = null

  constructor(private tickInterval: number = 1000) {}

  // Start the master timer
  start() {
    if (this.intervalId !== null) return

    this.intervalId = window.setInterval(() => {
      this.tick()
    }, this.tickInterval)
  }

  // Stop the master timer
  stop() {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId)
      this.intervalId = null
    }
  }

  // Register a new timer
  registerTimer(id: TimerId, callback: TimerCallback, interval: number) {
    this.timers.set(id, {
      id,
      interval,
      callback,
      lastRun: null,
      isRunning: true
    })
  }

  // Remove a timer
  removeTimer(id: TimerId) {
    this.timers.delete(id)
  }

  // Pause a specific timer
  pauseTimer(id: TimerId) {
    const timer = this.timers.get(id)
    if (timer) {
      timer.isRunning = false
    }
  }

  // Resume a specific timer
  resumeTimer(id: TimerId) {
    const timer = this.timers.get(id)
    if (timer) {
      timer.isRunning = true
    }
  }

  // Force run a specific timer
  async runTimer(id: TimerId) {
    const timer = this.timers.get(id)
    if (timer) {
      try {
        await timer.callback()
        timer.lastRun = Date.now()
      } catch (error) {
        console.error(`Timer ${id} failed:`, error)
      }
    }
  }

  // Private method to handle timer ticks
  private async tick() {
    const now = Date.now()

    for (const timer of this.timers.values()) {
      if (!timer.isRunning) continue

      const shouldRun = timer.lastRun === null || 
        (now - timer.lastRun) >= timer.interval

      if (shouldRun) {
        try {
          await timer.callback()
          timer.lastRun = now
        } catch (error) {
          console.error(`Timer ${timer.id} failed:`, error)
        }
      }
    }
  }
}

// Create a singleton instance
export const timerService = new TimerService()