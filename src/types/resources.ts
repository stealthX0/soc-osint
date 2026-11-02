export type OpSec = 'passive' | 'active';
export type Pricing = 'free' | 'freemium' | 'paid';
export type Flag = 'api' | 'local' | 'reg' | 'dork' | 'invite' | 'depr';

export interface Tool {
  id: number;
  name: string;
  url: string;
  /** index into ResourceData.categories */
  category: number;
  /** index into categories[category].subs */
  sub: number;
  group?: string;
  description?: string;
  bestFor?: string;
  input?: string;
  output?: string;
  opsec?: OpSec;
  opsecNote?: string;
  pricing?: Pricing;
  status?: string;
  flags: Flag[];
}

export interface Category { id: string; name: string; subs: { name: string; toolIds: number[] }[] }
export interface ResourceData { categories: Category[]; tools: Tool[] }

export interface PlaybookStep { title: string; detail: string; toolIds: number[]; active?: boolean }
export interface Playbook { id: string; title: string; summary: string; steps: PlaybookStep[] }

export interface Stats {
  tools: number; categories: number; playbooks: number; passive: number; active: number; free: number; withApi: number;
  perCategory: { id: string; name: string; count: number }[];
}
