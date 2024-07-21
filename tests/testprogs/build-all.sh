# Testing wrapper to build all the x86_64 derivations and ensure they works.
nix flake show --json | jq  '.packages."x86_64-linux" | keys[]' | xargs -I {} nix build .#{}
