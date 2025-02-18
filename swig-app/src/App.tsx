import { useEffect, useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import  Wallet  from './wallet'
import { useStore } from './store'
import { initializeBackgroundTasks, TaskIds } from './bg'
import { timerService } from './timer'

function App() {
  const watchedAddress = useStore(state => state.swigAddress)

  useEffect(() => {
    if (watchedAddress) {
      // Initialize background tasks when address is set
      initializeBackgroundTasks(watchedAddress)

      return () => {
        // Cleanup on unmount
        timerService.removeTimer(TaskIds.ACCOUNT_UPDATE)
        timerService.removeTimer(TaskIds.PRICE_UPDATE)
        timerService.stop()
      }
    }
  }, [watchedAddress])

  const setWatchedAddress = (address: string | null) => {
    if (!address) return
    useStore.getState().updateSwigAddress(address)
  }

  

  return (
    <>
      {watchedAddress && <Wallet />}
      {!watchedAddress && <div>
        <form onSubmit={(e) => {
          e.preventDefault()
          setWatchedAddress(e.currentTarget.elements.namedItem('address').value)
        }}>
        <label>Enter address</label>
        <input type="text" name="address" />
        <button type="submit">Submit</button>
        </form>
      </div>}
    </>
  )
}

export default App


