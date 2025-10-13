// Re-export the component and its types so consumers can import cleanly.

import MoneyIn from './MoneyIn'
export default MoneyIn; // <-- now default import works
export type { MoneyInProps } from './MoneyIn'
