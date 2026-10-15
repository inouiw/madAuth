// The blog's language select: each option's value is the path of the page in that language.
for (const select of document.querySelectorAll<HTMLSelectElement>('select[data-language-select]')) {
  select.addEventListener('change', () => location.assign(select.value));
  // Back from the other language, the page may come from the back/forward cache with the other option chosen.
  const own = select.querySelector<HTMLOptionElement>('option[selected]');
  window.addEventListener('pageshow', () => {
    if (own) select.value = own.value;
  });
}
