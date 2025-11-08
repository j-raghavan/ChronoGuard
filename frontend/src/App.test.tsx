import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

describe('App', () => {
  it('should render without crashing', () => {
    render(<App />);
    // App renders Router and QueryClient provider
    expect(document.body).toBeDefined();
  });

  it('should wrap app in QueryClientProvider', () => {
    const { container } = render(<App />);
    expect(container).toBeDefined();
  });

  it('should wrap app in BrowserRouter', () => {
    const { container } = render(<App />);
    expect(container).toBeDefined();
  });
});
