
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

type TransactionType = 'deposit' | 'withdrawal' | 'trade'
type Theme = 'light' | 'dark'
type Currency = 'USD' | 'EUR' | 'GBP'

interface Asset {
  id: string
  symbol: string
  name: string
  amount: number
  icon?: string
  chain: string
  change24h: number
}

interface Transaction {
  id: number
  amount: number
  type: TransactionType
  chain: string
  timestamp: string
  assetId?: string
}

interface Settings {
  theme: Theme
  currency: Currency
  decimals: number
}
type PriceData = {
  [mint: string]: {
    price: number
    change24h: number
    lastUpdated: number
  }
}

interface State {
  swigAddress: string | null
  balance: number
  assets: Asset[]
  transactions: Transaction[]
  prices: PriceData
  settings: Settings
  error: string | null
}

interface Actions {
  updateSwigAddress: (address: string) => void
  updateAsset: (assetId: string, updates: Partial<Asset>) => void
  updateAssets: (updates: Partial<Asset>[]) => void
  updatePrices: (updates: Partial<PriceData>) => void
  addAsset: (asset: Omit<Asset, 'id'>) => void
  removeAsset: (assetId: string) => void
  updateSettings: (settings: Partial<Settings>) => void
  setError: (error: string) => void
}

const initialState: State = {
  swigAddress: null,
  balance: 0,
  error: null,
  assets: [
  ],
  prices: {},
  transactions: [],
  settings: {
    theme: 'light',
    currency: 'USD',
    decimals: 2
  }
}

export const useStore = create<State & Actions>()(
  persist(
    (set) => ({
      ...initialState,
      updateSwigAddress: (address) => set((state) => ({
        swigAddress: address
      })),
      updateAsset: (assetId, updates) => set((state) => ({
        assets: state.assets.map(asset => 
          asset.id === assetId ? { ...asset, ...updates } : asset
        )
      })),
      updatePrices: (updates) => set((state) => ({
        prices: { ...state.prices, ...updates }
      })),
      updateAssets: (updates) => set((state) => ({
        assets: state.assets.map(asset => ({
          ...asset,
          ...updates
        }))
      })),


      addAsset: (asset) => set((state) => ({
        assets: [...state.assets, { ...asset, id: Date.now().toString() }]
      })),

      removeAsset: (assetId) => set((state) => ({
        assets: state.assets.filter(asset => asset.id !== assetId)
      })),

      updateSettings: (newSettings) => set((state) => ({
        settings: { ...state.settings, ...newSettings }
      })),
      
  
      setError: (error) => set({ error })
    }),
    {
      name: 'wallet-storage'
    }
  )
)

// Selector hooks
export const useBalance = () => useStore((state) => state.balance)
export const useAssets = () => useStore((state) => state.assets)
export const useTransactions = () => useStore((state) => state.transactions)
export const useSettings = () => useStore((state) => state.settings)
export const useWalletActions = () => ({
  updateAsset: useStore((state) => state.updateAsset),
  addAsset: useStore((state) => state.addAsset),
  removeAsset: useStore((state) => state.removeAsset),
  updateSettings: useStore((state) => state.updateSettings)
})
