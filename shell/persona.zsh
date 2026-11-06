# Optional, quiet Persona prompt marker. Source from Zsh startup; does not select
# an identity, modify PROMPT, or mutate any process that already exists.
autoload -Uz add-zsh-hook

if [[ ${_PERSONA_ZSH_ADAPTER_ACTIVE-} == 1 ]]; then
  # Re-register only the private callback; do not invoke public shell functions.
  add-zsh-hook -d precmd _persona_zsh_refresh_marker 2>/dev/null
  add-zsh-hook precmd _persona_zsh_refresh_marker
elif (( ! $+functions[persona_zsh_deactivate] && ! $+functions[persona_prompt_marker] )); then
  function _persona_zsh_refresh_marker() {
    local marker
    marker="$(command persona shell zsh marker 2>/dev/null)" || marker=''
    typeset -g _PERSONA_PROMPT_MARKER="$marker"
  }

  function persona_prompt_marker() {
    print -rn -- "${_PERSONA_PROMPT_MARKER-}"
  }

  function persona_zsh_deactivate() {
    add-zsh-hook -d precmd _persona_zsh_refresh_marker 2>/dev/null
    unset _PERSONA_PROMPT_MARKER _PERSONA_ZSH_ADAPTER_ACTIVE
    unfunction persona_zsh_deactivate _persona_zsh_refresh_marker persona_prompt_marker
  }

  add-zsh-hook -d precmd _persona_zsh_refresh_marker 2>/dev/null
  add-zsh-hook precmd _persona_zsh_refresh_marker
  typeset -g _PERSONA_ZSH_ADAPTER_ACTIVE=1
fi

rehash
