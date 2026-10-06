import { HeadContent, Outlet, Scripts, createRootRoute } from '@tanstack/react-router'
import { Shell } from '~/components/Shell'
import appCss from '~/styles.css?url'

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { name: 'referrer', content: 'no-referrer' },
      { title: 'Cipherroom — end-to-end encrypted messaging' },
    ],
    links: [{ rel: 'stylesheet', href: appCss }],
  }),
  component: Root,
})

function Root() {
  return (
    <html lang="en" className="h-full">
      <head>
        <HeadContent />
      </head>
      <body className="h-full">
        {/* Everything behind the sign-in screen depends on keys that are only ever usable inside this browser. */}
        <Shell>
          <Outlet />
        </Shell>
        <Scripts />
      </body>
    </html>
  )
}
