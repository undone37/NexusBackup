import './app.css';
import { mount } from 'svelte';
import { initTheme } from './lib/theme.svelte';
import App from './App.svelte';

initTheme();
mount(App, { target: document.getElementById('app')! });
