// AWS SDK clients in n8n are always handed explicit credentials. This rule bans
// the SDK helpers that auto-discover credentials from the host, so credential
// resolution stays routed through getSystemCredentials() and the
// awsSystemCredentialsAccess setting.
import { ESLintUtils, type TSESTree } from '@typescript-eslint/utils';

const BANNED_MODULES = ['@aws-sdk/credential-providers', '@aws-sdk/credential-provider-node'];

const BANNED_NAMES = ['fromNodeProviderChain', 'defaultProvider'];

// Modules whose entire relevant export surface is credential discovery, so simply
// reaching the module (namespace import, dynamic `import()`, or `require()`) is enough
// to surface a banned helper. `@aws-sdk/credential-providers` is intentionally excluded:
// it also exports the allowed `fromTemporaryCredentials`, so module-level access there is
// not by itself a violation — the consumer selects a specific name (see the per-name checks).
const DISCOVERY_ONLY_MODULES = ['@aws-sdk/credential-provider-node'];

const isBannedModule = (source: string): boolean => BANNED_MODULES.includes(source);

const isBannedName = (name: string): boolean => BANNED_NAMES.includes(name);

export const NoAwsCredentialDiscoveryImportsRule = ESLintUtils.RuleCreator.withoutDocs({
	meta: {
		type: 'problem',
		docs: {
			description:
				'AWS SDK clients in n8n are always handed explicit credentials. This rule bans the SDK helpers that auto-discover credentials from the host (`fromNodeProviderChain`, `defaultProvider`), so credential resolution stays routed through getSystemCredentials() and the awsSystemCredentialsAccess setting.',
		},
		messages: {
			noAwsCredentialDiscovery:
				"Do not import '{{name}}'. Pass explicit `credentials` to AWS SDK clients; host credential discovery must go through getSystemCredentials().",
			noAwsCredentialDiscoveryModule:
				"Do not import from '{{module}}' to reach credential-discovery helpers. Pass explicit `credentials` to AWS SDK clients; host credential discovery must go through getSystemCredentials().",
		},
		schema: [],
	},
	defaultOptions: [],
	create(context) {
		return {
			ImportDeclaration(node) {
				const source = node.source.value;
				if (!isBannedModule(source)) return;

				// Top-level type-only import (`import type { defaultProvider } from ...`) is harmless.
				if (node.importKind === 'type') return;

				for (const specifier of node.specifiers) {
					if (specifier.type === 'ImportNamespaceSpecifier') {
						if (DISCOVERY_ONLY_MODULES.includes(source)) {
							context.report({
								node: specifier,
								messageId: 'noAwsCredentialDiscoveryModule',
								data: { module: source },
							});
						}
						continue;
					}

					if (specifier.type !== 'ImportSpecifier') continue;
					// Per-specifier type-only import (`import { type defaultProvider } from ...`).
					if (specifier.importKind === 'type') continue;

					const importedName =
						specifier.imported.type === 'Identifier'
							? specifier.imported.name
							: specifier.imported.value;
					if (isBannedName(importedName)) {
						context.report({
							node: specifier,
							messageId: 'noAwsCredentialDiscovery',
							data: { name: importedName },
						});
					}
				}
			},

			// Re-export laundering: `export { defaultProvider } from '@aws-sdk/credential-provider-node'`.
			ExportNamedDeclaration(node) {
				if (!node.source) return;
				if (!isBannedModule(node.source.value)) return;
				if (node.exportKind === 'type') return;

				for (const specifier of node.specifiers) {
					if (specifier.exportKind === 'type') continue;

					// `local` is the name in the source module — the one that must not be re-surfaced.
					const localName =
						specifier.local.type === 'Identifier' ? specifier.local.name : specifier.local.value;
					if (isBannedName(localName)) {
						context.report({
							node: specifier,
							messageId: 'noAwsCredentialDiscovery',
							data: { name: localName },
						});
					}
				}
			},

			// Wholesale re-export laundering: `export * from '@aws-sdk/credential-provider-node'`.
			// Flagged for BOTH modules (`isBannedModule`), unlike the other module-level forms.
			// A namespace import / dynamic `import()` / `require()` of `credential-providers` lets the
			// consumer locally select a specific name (typically the allowed `fromTemporaryCredentials`),
			// so those are allowed for that module. `export *` makes no such selection — it
			// unconditionally re-surfaces every export, banned helpers included, to other modules.
			ExportAllDeclaration(node) {
				if (node.exportKind === 'type') return;
				if (!isBannedModule(node.source.value)) return;
				context.report({
					node,
					messageId: 'noAwsCredentialDiscoveryModule',
					data: { module: node.source.value },
				});
			},

			// Dynamic import: `import('@aws-sdk/credential-provider-node')`. Flagged at the module
			// level only for discovery-only modules — same asymmetry as the namespace import.
			// `await import('@aws-sdk/credential-providers')` is allowed: the consumer destructures a
			// specific name (typically the allowed `fromTemporaryCredentials`), which is the form
			// ENT-66's lazy SDK import uses; a destructured banned name there is an accepted residual.
			ImportExpression(node) {
				const { source } = node;
				if (source.type !== 'Literal' || typeof source.value !== 'string') return;
				if (!DISCOVERY_ONLY_MODULES.includes(source.value)) return;
				context.report({
					node,
					messageId: 'noAwsCredentialDiscoveryModule',
					data: { module: source.value },
				});
			},

			// `require('@aws-sdk/credential-provider-node')`. Flagged at the module level only for
			// discovery-only modules — same asymmetry as the namespace / dynamic import. A
			// `require('@aws-sdk/credential-providers')` destructure selects a specific name (typically
			// the allowed `fromTemporaryCredentials`), so it is allowed; a destructured banned name
			// there is an accepted residual. `require.resolve(...)` only resolves a path string and
			// discovers nothing, so it is intentionally not flagged.
			CallExpression(node: TSESTree.CallExpression) {
				if (node.callee.type !== 'Identifier' || node.callee.name !== 'require') return;
				const [arg] = node.arguments;
				if (!arg || arg.type !== 'Literal' || typeof arg.value !== 'string') return;
				if (!DISCOVERY_ONLY_MODULES.includes(arg.value)) return;
				context.report({
					node,
					messageId: 'noAwsCredentialDiscoveryModule',
					data: { module: arg.value },
				});
			},
		};
	},
});
