import { invoke } from '@tauri-apps/api'
import React, { createContext, useCallback, useEffect, useState } from 'react'
import { useHistory } from 'react-router-dom'
import { Coin, TClientDetails } from '../types'

type TClientContext = {
  clientDetails?: TClientDetails
  gasPrice?: Coin
  logIn: (clientDetails: TClientDetails) => void
  logOut: () => void
}

export const ClientContext = createContext({} as TClientContext)

export const ClientContextProvider = ({
  children,
}: {
  children: React.ReactNode
}) => {
  const [clientDetails, setClientDetails] = useState<TClientDetails>()
  const [gasPrice, setGasPrice] = useState<Coin>()

  const history = useHistory()

  useEffect(() => {
    !clientDetails ? history.push('/signin') : history.push('/bond')
  }, [clientDetails])

  const logIn = async (clientDetails: TClientDetails) => {
    await invoke('get_gas_price')
      .then((res) => setGasPrice(res as Coin))
      .catch((e) => console.log(e))
    setClientDetails(clientDetails)
  }

  const logOut = () => setClientDetails(undefined)

  return (
    <ClientContext.Provider
      value={{
        clientDetails,
        gasPrice,
        logIn,
        logOut,
      }}
    >
      {children}
    </ClientContext.Provider>
  )
}
