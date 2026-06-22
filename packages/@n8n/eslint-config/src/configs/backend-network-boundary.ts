import tseslint from 'typescript-eslint';

/**
 * Backend network boundary.
 *
 * Backend outbound HTTP must go through the `@n8n/backend-network` factory so
 * SSRF/DNS guarding and proxy handling stay centrally controlled. This turns on
 * `n8n-local-rules/no-uncentralized-http` for every Node backend package (it is
 * part of `nodeConfig`).
 *
 * Out of natural scope:
 * - Frontend packages
 * - `@n8n/backend-network` itself
 *
 * To request a new exception, see  `packages/@n8n/backend-network/README.md`
 */

export const backendNetworkBoundaryConfig = tseslint.config({
	rules: {
		'n8n-local-rules/no-uncentralized-http': [
			'error',
			{
				allow: ['packages/@n8n/benchmark/'],
			},
		],
	},
});
