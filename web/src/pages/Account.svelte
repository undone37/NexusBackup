<script lang="ts">
  // My account: the signed-in user's own API tokens (Phase 14d).
  import { session } from '../lib/session.svelte';
  import { t } from '../lib/i18n';
  import ApiTokens from '../components/ApiTokens.svelte';
</script>

<div class="page-head">
  <h1>{t.account.title}</h1>
  <p class="lede">{t.account.lede(session.user?.name ?? '', t.roles[session.user?.role ?? 'operator'])}</p>
</div>

<ApiTokens />
