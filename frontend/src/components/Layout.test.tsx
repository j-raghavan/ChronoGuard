import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { Layout } from './Layout';

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useLocation: () => ({ pathname: '/' }),
    Outlet: () => <div>Outlet Content</div>,
  };
});

describe('Layout', () => {
  it('should render ChronoGuard title', () => {
    render(
      <BrowserRouter>
        <Layout />
      </BrowserRouter>
    );

    expect(screen.getByText('ChronoGuard')).toBeInTheDocument();
  });

  it('should render navigation links', () => {
    render(
      <BrowserRouter>
        <Layout />
      </BrowserRouter>
    );

    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Agents')).toBeInTheDocument();
    expect(screen.getByText('Policies')).toBeInTheDocument();
    expect(screen.getByText('Audit Log')).toBeInTheDocument();
  });

  it('should render outlet content', () => {
    render(
      <BrowserRouter>
        <Layout />
      </BrowserRouter>
    );

    expect(screen.getByText('Outlet Content')).toBeInTheDocument();
  });

  it('should have navigation items with correct hrefs', () => {
    render(
      <BrowserRouter>
        <Layout />
      </BrowserRouter>
    );

    const dashboardLink = screen.getByText('Dashboard').closest('a');
    const agentsLink = screen.getByText('Agents').closest('a');
    const policiesLink = screen.getByText('Policies').closest('a');
    const auditLink = screen.getByText('Audit Log').closest('a');

    expect(dashboardLink).toHaveAttribute('href', '/');
    expect(agentsLink).toHaveAttribute('href', '/agents');
    expect(policiesLink).toHaveAttribute('href', '/policies');
    expect(auditLink).toHaveAttribute('href', '/audit');
  });
});
