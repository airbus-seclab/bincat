## Ocaml
* Utiliser au moins TROIS caractères pour toutes les variables (oui, si, vraiment.)
* gérer la mémoire par octet pas par mot (pour l'init)
* sortir les informations nécessaires à l'affichage de la teinte
* gérer les questions "synchrones" avec l'interface IDA pour quand il y a une décision à prendre (trop de branches par exemple) ... utiliser un pipe (attention à Windows) ?
* gérer des chemins UTF-8 dans le .ini ?
* tests QEMU

## Plugin IDA
* gérer des traces multiples à la même adresse
* importer les valeurs concrètes depuis le debugger (mémoire et registres)
* fenetre de registre jolie (couleur pour la teinte)
* colorer les lignes teintées

## Global
* faire marcher `bincat` sous windows ?
* spécifier les sections de data et leurs adresses (physiques/virtuelles) pour permettre à bincat de les lire dans le binaire direct
