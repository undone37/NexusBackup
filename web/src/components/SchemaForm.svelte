<script lang="ts">
  import { t } from '../lib/i18n';
  import { initValues, isList, properties, supported, type FormItem, type FormValues } from '../lib/schema';
  import type { JsonSchema } from '../lib/types';
  import SchemaForm from './SchemaForm.svelte';

  // Form fields generated from a plugin's JSON-Schema subset (config_schema / params_schema).
  // Values live in `values` (see lib/schema.ts: arrays as newline-separated text);
  // `buildValue` turns them into the JSON to send and yields the `errors` shown here.
  let {
    schema,
    values = $bindable(),
    errors = {},
    secretFields = [],
    secretSet = {},
  }: {
    schema: JsonSchema | undefined;
    values: FormValues;
    errors?: Record<string, string>;
    secretFields?: string[];
    secretSet?: Record<string, boolean>;
  } = $props();

  const uid = $props.id();
  const required = $derived(schema?.required ?? []);
  const all = $derived(properties(schema));
  // Scalars in the grid; booleans and lists full width below it.
  const scalars = $derived(all.filter(([, p]) => supported(p) && p.type !== 'boolean' && p.type !== 'array'));
  const wide = $derived(all.filter(([, p]) => supported(p) && !isList(p) && (p.type === 'boolean' || p.type === 'array')));
  // lists of objects (contract v1.6): one sub-form per entry
  const lists = $derived(all.filter(([, p]) => supported(p) && isList(p)));
  const itemsOf = (name: string) => (Array.isArray(values[name]) ? (values[name] as FormItem[]) : []);
  const itemErrors = (name: string, i: number) =>
    Object.fromEntries(
      Object.entries(errors)
        .filter(([k]) => k.startsWith(`${name}.${i}.`))
        .map(([k, e]) => [k.slice(`${name}.${i}.`.length), e]),
    );
  function addItem(name: string, p: JsonSchema) {
    values[name] = [...itemsOf(name), { values: initValues(p.items), set: {} }];
  }
  function removeItem(name: string, i: number) {
    // later entries move up: their stored secrets are bound to their old position (enter them again)
    values[name] = itemsOf(name)
      .filter((_, j) => j !== i)
      .map((x, j) => (j >= i ? { ...x, set: {} } : x));
  }
  const unsupported = $derived(all.filter(([, p]) => !supported(p)));

  const label = (name: string, p: JsonSchema) => p.title || name;
  const hintOf = (name: string, p: JsonSchema) => {
    const parts = [p.description];
    if (secretFields.includes(name)) parts.push(secretSet[name] ? t.writeOnlyKeep : t.writeOnlyHint);
    if (p.type === 'array') parts.push(t.schema.lines);
    return parts.filter(Boolean).join(' ');
  };
  const isPassword = (name: string, p: JsonSchema) => secretFields.includes(name) || p.format === 'password';
  const isRequired = (name: string) => required.includes(name) && !(secretFields.includes(name) && secretSet[name]);
  const textOf = (v: unknown) => (v === null || v === undefined ? '' : String(v));
</script>

{#snippet hints(name: string, p: JsonSchema, id: string)}
  {@const h = hintOf(name, p)}
  <!-- one hint row per field (form-grid subgrid: label | control | hint) -->
  {#if errors[name]}<div class="hint bad" id="{id}-err">{errors[name]}</div>
  {:else if h}<div class="hint" id="{id}-hint">{h}</div>{/if}
{/snippet}

{#if scalars.length}
  <div class="form-grid">
    {#each scalars as [name, p] (name)}
      {@const id = `${uid}-${name}`}
      {@const desc = errors[name] ? `${id}-err` : hintOf(name, p) ? `${id}-hint` : undefined}
      <div class="field">
        <label for={id}>{label(name, p)}</label>
        {#if p.enum}
          <select {id} bind:value={values[name]} required={isRequired(name)} aria-invalid={!!errors[name]} aria-describedby={desc}>
            {#if !isRequired(name)}<option value="">{t.schema.unset}</option>{/if}
            {#each p.enum as o (o)}<option value={o}>{o}</option>{/each}
          </select>
        {:else if p.type === 'integer'}
          <input
            {id}
            type="number"
            step="1"
            min={p.minimum ?? (p.format === 'port' ? 1 : undefined)}
            max={p.maximum ?? (p.format === 'port' ? 65535 : undefined)}
            bind:value={values[name]}
            required={isRequired(name)}
            aria-invalid={!!errors[name]}
            aria-describedby={desc}
          />
        {:else if isPassword(name, p)}
          <input
            {id}
            type="password"
            value={textOf(values[name])}
            oninput={(e) => (values[name] = e.currentTarget.value)}
            autocomplete="new-password"
            required={isRequired(name)}
            maxlength={p.maxLength}
            aria-invalid={!!errors[name]}
            aria-describedby={desc}
          />
        {:else}
          <input
            {id}
            class:mono={!!p.pattern || p.format === 'hostname'}
            value={textOf(values[name])}
            oninput={(e) => (values[name] = e.currentTarget.value)}
            required={isRequired(name)}
            maxlength={p.maxLength}
            placeholder={p.default !== undefined ? String(p.default) : undefined}
            autocomplete="off"
            spellcheck="false"
            aria-invalid={!!errors[name]}
            aria-describedby={desc}
          />
        {/if}
        {@render hints(name, p, id)}
      </div>
    {/each}
  </div>
{/if}

{#each wide as [name, p] (name)}
  {@const id = `${uid}-${name}`}
  {@const desc = errors[name] ? `${id}-err` : hintOf(name, p) ? `${id}-hint` : undefined}
  <div class="field">
    {#if p.type === 'boolean'}
      <label class="inline-check"
        ><input
          type="checkbox"
          checked={!!values[name]}
          onchange={(e) => (values[name] = e.currentTarget.checked)}
          aria-describedby={desc}
        />{label(name, p)}</label
      >
    {:else}
      <label for={id}>{label(name, p)}</label>
      <textarea
        {id}
        value={textOf(values[name])}
        oninput={(e) => (values[name] = e.currentTarget.value)}
        spellcheck="false"
        aria-invalid={!!errors[name]}
        aria-describedby={desc}
      ></textarea>
    {/if}
    {@render hints(name, p, id)}
  </div>
{/each}

{#each lists as [name, p] (name)}
  {@const id = `${uid}-${name}`}
  {@const items = itemsOf(name)}
  <fieldset class="schema-list" aria-describedby={hintOf(name, p) || errors[name] ? `${id}-hint` : undefined}>
    <legend>{label(name, p)}</legend>
    {#if errors[name]}<div class="hint bad" id="{id}-hint">{errors[name]}</div>
    {:else if p.description}<div class="hint" id="{id}-hint">{p.description}</div>{/if}
    {#each items as it, i (i)}
      <div class="schema-item">
        <div class="schema-item-head">
          <strong>{t.schema.item(i + 1)}</strong>
          <button type="button" class="link" onclick={() => removeItem(name, i)} aria-label="{t.schema.removeItem}: {label(name, p)} {i + 1}"
            >{t.schema.removeItem}</button
          >
        </div>
        <SchemaForm schema={p.items} bind:values={it.values} errors={itemErrors(name, i)} {secretFields} secretSet={it.set} />
      </div>
    {:else}
      <p class="muted">{t.schema.noItems}</p>
    {/each}
    <p>
      <button type="button" onclick={() => addItem(name, p)} disabled={p.maxItems !== undefined && items.length >= p.maxItems}
        >{t.schema.addItem}</button
      >
    </p>
  </fieldset>
{/each}

{#each unsupported as [name] (name)}
  <p class="muted">{t.schema.unsupported(name)}</p>
{/each}

<style>
  .schema-item {
    border-top: 1px solid var(--border);
    padding-top: 0.6rem;
    margin-bottom: 0.4rem;
  }
  .schema-item-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 0.4rem;
  }
</style>
