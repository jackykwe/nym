import React from 'react';
import { Button, Grid, Stack } from '@mui/material';
import testNode from 'src/assets/test-node-illustration.jpg';
import { OverviewDescription } from '../components/OverviewDescription';

const content = [
  {
    title: 'How is works',
    description:
      'This is your APY playground - play with the parameters on left to see estimated rewards on the right side',
  },
  {
    title: 'Test path',
    description:
      'This is your APY playground - play with the parameters on left to see estimated rewards on the right side',
  },
  {
    title: 'Results',
    description:
      'This is your APY playground - play with the parameters on left to see estimated rewards on the right side',
  },
];

export const Overview = ({ onStartTest }: { onStartTest: () => void }) => (
  <Grid container spacing={2} justifyContent="center">
    <Grid item xs={12} md={6}>
      <img src={testNode} style={{ borderRadius: 8 }} />
    </Grid>
    <Grid item container direction="column" xs={12} xl={6}>
      <Grid item>
        <Stack>{content.map(OverviewDescription)}</Stack>
      </Grid>
      <Grid item>
        <Button variant="contained" fullWidth disableElevation onClick={onStartTest}>
          Start test
        </Button>
      </Grid>
    </Grid>
  </Grid>
);
