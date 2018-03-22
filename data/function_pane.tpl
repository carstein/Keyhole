<div id="{id}" class="pane">
  <table class="function_pane">
    <thead>
      <tr>
        <th>Calls from {id}</th>
      </tr>
    </thead>
    <tbody>
      {calls_rows}
    </tbody>
  </table>
  <table  class="function_pane">
    <thead>
      <tr>
        <th>XREFs to {id}</th>
      </tr>
    </thead>
    <tbody>
      {xref_rows}
    </tbody>
  </table>
  <div class="legend">
    <table>
      <tbody>
        <tr>
          <td class="data_op"></td>
          <td>Data operations (mov ...)</td>
        <tr>
        <tr>
          <td class="fp_op"></td>
          <td>Floating point operations</td>
        <tr>
        <tr>
          <td class="arthm_op"></td>
          <td>Arthmetic operations (add, xor, shr ...)</td>
        <tr>
        <tr>
          <td class="df_op"></td>
          <td>Dataflow operations (call, cmp, jmp ...)</td>
        <tr>
        <tr>
          <td class="other_op"></td>
          <td>Other operations</td>
        <tr>
      </tbody>
    </table>
  </div>
  <div class="fingerprint">
    {img}
  </div>
</div>
