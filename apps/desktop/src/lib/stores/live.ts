import type { ServerMessage, Snapshot } from '../api/types';

export interface LiveState {
  sequence: number;
  connected: boolean;
  needsResync: boolean;
  serviceStatus: string;
}

export const initialLiveState: LiveState = {
  sequence: 0,
  connected: false,
  needsResync: false,
  serviceStatus: 'unknown'
};

export function reduceLiveMessage(state: LiveState, message: ServerMessage): LiveState {
  if (state.needsResync) return state;

  if (message.type === 'resync_required') {
    return { ...state, connected: false, needsResync: true };
  }

  const { data } = message;
  if (data.sequence <= state.sequence) return state;
  if (data.sequence > state.sequence + 1) {
    return { ...state, connected: false, needsResync: true };
  }

  return {
    sequence: data.sequence,
    connected: true,
    needsResync: false,
    serviceStatus: data.payload.type === 'service_status' ? data.payload.data.state : state.serviceStatus
  };
}

export function applySnapshot(_: LiveState, snapshot: Snapshot): LiveState {
  return {
    sequence: snapshot.sequence,
    connected: true,
    needsResync: false,
    serviceStatus: snapshot.service_status
  };
}
