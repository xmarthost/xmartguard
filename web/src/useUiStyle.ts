import { useSyncExternalStore } from 'react';
import { getUiStyle, subscribeUiStyle, type UiStyle } from './theme';

/** The portal's page style (Appearance » Style). */
export function useUiStyle(): UiStyle {
  return useSyncExternalStore(subscribeUiStyle, getUiStyle, getUiStyle);
}
