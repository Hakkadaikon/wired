import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://hakkadaikon.github.io',
  base: '/wired/guide',
  integrations: [
    starlight({
      title: 'wired guide',
      defaultLocale: 'en',
      locales: {
        en: { label: 'English' },
        ja: { label: '日本語', lang: 'ja' },
      },
      sidebar: [
        { label: 'Getting started', translations: { ja: 'はじめに' }, items: [{ autogenerate: { directory: 'getting-started' } }] },
        { label: 'TLS & crypto', translations: { ja: 'TLS と暗号' }, items: [{ autogenerate: { directory: 'tls' } }] },
        { label: 'QUIC', items: [{ autogenerate: { directory: 'quic' } }] },
        { label: 'HTTP/3', items: [{ autogenerate: { directory: 'h3' } }] },
        { label: 'WebTransport', items: [{ autogenerate: { directory: 'wt' } }] },
        { label: 'MoQT', items: [{ autogenerate: { directory: 'moqt' } }] },
      ],
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/hakkadaikon/wired' }],
    }),
  ],
});
