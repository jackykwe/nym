import {
  FormControl,
  FormControlLabel,
  FormLabel,
  Radio,
  RadioGroup,
} from '@material-ui/core'
import React from 'react'
import { EnumNodeType } from '../types/global'

export const NodeTypeSelector = ({
  disabled,
  nodeType,
  setNodeType,
}: {
  disabled: boolean
  nodeType: EnumNodeType
  setNodeType: (nodeType: EnumNodeType) => void
}) => {
  const handleNodeTypeChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setNodeType(e.target.value as EnumNodeType)

  return (
    <FormControl component="fieldset">
      <FormLabel component="legend">Select node type</FormLabel>
      <RadioGroup
        aria-label="nodeType"
        name="nodeTypeRadio"
        value={nodeType}
        onChange={handleNodeTypeChange}
        style={{ display: 'block' }}
      >
        <FormControlLabel
          value={EnumNodeType.mixnode}
          control={<Radio />}
          label="Mixnode"
          disabled={disabled}
        />
        <FormControlLabel
          value={EnumNodeType.gateway}
          control={<Radio />}
          label="Gateway"
          disabled={disabled}
        />
      </RadioGroup>
    </FormControl>
  )
}
