<script>
  // The Doctor view bound to the real backend.
  import { doctorApi } from '../lib/bridge/api.js';
  import DoctorScreen from '../lib/doctor/DoctorScreen.svelte';
</script>

<section class="view" data-view="doctor">
  <DoctorScreen api={doctorApi} />
</section>

<style>
  .view { height: 100%; overflow: auto; background: var(--bg-1); }
</style>
