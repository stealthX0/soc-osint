import { lazy, Suspense } from 'react';
import { Layout } from './components/Layout';
import { Routes, Link } from './lib/router';
import { Spinner } from './components/ui';
import { Dashboard } from './pages/Dashboard';

// Tool pages are code-split so the landing page stays small; the 250 KB resource dataset
// only loads with the directory/playbooks pages.
const IpPage = lazy(() => import('./pages/IpPage'));
const DnsPage = lazy(() => import('./pages/DnsPage'));
const DomainPage = lazy(() => import('./pages/DomainPage'));
const UrlPage = lazy(() => import('./pages/UrlPage'));
const EmailPage = lazy(() => import('./pages/EmailPage'));
const NetworkPage = lazy(() => import('./pages/NetworkPage'));
const FilePage = lazy(() => import('./pages/FilePage'));
const UtilitiesPage = lazy(() => import('./pages/UtilitiesPage'));
const ResourcesPage = lazy(() => import('./pages/ResourcesPage'));
const PlaybooksPage = lazy(() => import('./pages/PlaybooksPage'));

function NotFound() {
  return (
    <div className="py-20 text-center">
      <p className="font-mono text-5xl text-teal">404</p>
      <p className="mt-2 text-muted">That page does not exist.</p>
      <Link to="/" className="mt-4 inline-block text-teal hover:underline">Back to the dashboard</Link>
    </div>
  );
}

export function App() {
  return (
    <Layout>
      <Suspense fallback={<div className="py-10"><Spinner label="Loading" /></div>}>
        <Routes
          fallback={<NotFound />}
          routes={[
            { path: '/', render: () => <Dashboard /> },
            { path: '/ip', render: () => <IpPage /> },
            { path: '/dns', render: () => <DnsPage /> },
            { path: '/domain', render: () => <DomainPage /> },
            { path: '/url', render: () => <UrlPage /> },
            { path: '/email', render: () => <EmailPage /> },
            { path: '/file', render: () => <FilePage /> },
            { path: '/network', render: () => <NetworkPage /> },
            { path: '/utilities', render: () => <UtilitiesPage /> },
            { path: '/resources', render: () => <ResourcesPage /> },
            { path: '/playbooks', render: () => <PlaybooksPage /> },
            { path: '/playbooks/:id', render: (p) => <PlaybooksPage id={p.id} /> },
          ]}
        />
      </Suspense>
    </Layout>
  );
}
