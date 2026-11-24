import { mount } from 'svelte';
import './styles/fonts.css';
import './styles/tokens.css';
import './styles/base.css';
import './styles/pane.css';
import App from './App.svelte';

mount(App, { target: document.getElementById('app') });
