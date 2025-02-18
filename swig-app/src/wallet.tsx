import React, { useState, useEffect } from 'react'
import { useBalance, useAssets, useTransactions, useSettings, useWalletActions } from '@/store'
import { Card, CardHeader, CardContent } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

// Format currency based on settings
const formatCurrency = (amount: number, currency: string, decimals: number) => {
  const formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency,
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  })
  return formatter.format(amount)
}

const AssetCard: React.FC<{ asset: any }> = ({ asset }) => {
  const settings = useSettings()
  
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="font-bold">{asset.name}</h3>
            <p className="text-sm text-gray-500">{asset.symbol}</p>
          </div>
          <div className="text-right">
            <p className="font-bold">
              {formatCurrency(asset.value * asset.amount, settings.currency, settings.decimals)}
            </p>
            <p className={`text-sm ${asset.change24h >= 0 ? 'text-green-500' : 'text-red-500'}`}>
              {asset.change24h >= 0 ? '↑' : '↓'} {Math.abs(asset.change24h)}%
            </p>
          </div>
        </div>
        <div className="mt-2 text-sm text-gray-500">
          {asset.amount} {asset.symbol}
        </div>
      </CardContent>
    </Card>
  )
}


const Wallet = () => {

  
  const balance = useBalance()
  const assets = useAssets()
  const transactions = useTransactions()
  const settings = useSettings()
  const { updateSettings } = useWalletActions()

  // Apply theme
  useEffect(() => {
    document.documentElement.classList.toggle('dark', settings.theme === 'dark')
  }, [settings.theme])

  const totalAssetValue = assets.reduce((sum, asset) => sum + (asset.value * asset.amount), 0)

  return (
    <div className="max-w-4xl mx-auto p-4">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Wallet</h1>
        <select
          value={settings.theme}
          onChange={(e) => updateSettings({ theme: e.target.value as 'light' | 'dark' })}
          className="p-2 border rounded bg-transparent"
        >
          <option value="light">Light Mode</option>
          <option value="dark">Dark Mode</option>
        </select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <Card>
          <CardContent className="p-6">
            <h2 className="text-lg font-semibold mb-2">Available Balance</h2>
            <p className="text-3xl font-bold">
              {formatCurrency(balance, settings.currency, settings.decimals)}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <h2 className="text-lg font-semibold mb-2">Total Assets Value</h2>
            <p className="text-3xl font-bold">
              {formatCurrency(totalAssetValue, settings.currency, settings.decimals)}
            </p>
            <p className="text-sm text-gray-500 mt-2">
              Across {assets.length} assets
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="assets" className="space-y-4">
        <TabsList>
          <TabsTrigger value="assets">Assets</TabsTrigger>
          <TabsTrigger value="transactions">Transactions</TabsTrigger>
        </TabsList>

        <TabsContent value="assets" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-1">
            {assets.map((asset) => (
              <AssetCard key={asset.id} asset={asset} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="transactions">
          <Card>
            <CardContent className="p-4">
              <div className="space-y-2">
                {transactions.map((tx) => (
                  <div 
                    key={tx.id} 
                    className="flex justify-between items-center p-3 bg-secondary rounded-lg"
                  >
                    <div>
                      <span className="font-medium capitalize">{tx.type}</span>
                      <span className="text-sm text-gray-500 block">
                        {new Date(tx.timestamp).toLocaleDateString()} 
                        {new Date(tx.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <span className={`font-bold ${
                      tx.type === 'deposit' ? 'text-green-500' : 'text-red-500'
                    }`}>
                      {tx.type === 'deposit' ? '+' : '-'}
                      {formatCurrency(tx.amount, settings.currency, settings.decimals)}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

     
    </div>
  )
}

export default Wallet