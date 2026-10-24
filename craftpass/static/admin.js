/* CraftPass progressive enhancement.
 * The console is fully functional without JavaScript; this file only adds
 * a confirmation step to destructive forms (data-confirm attribute).
 */
document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  const message = form.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
