import { createContext, useContext } from 'react'

// GET /meta: models, sensitivity levels, data access areas, PII tags and labels, control and stage names.
export const MetaContext = createContext(null)

export const useMeta = () => useContext(MetaContext)
