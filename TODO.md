## Ocaml
* gérer la mémoire par octet pas par mot (pour l'init)
* sortir les informations nécessaires à l'affichage de la teinte
* gérer les questions "synchrones" avec l'interface IDA pour quand il y a une décision à prendre (trop de branches par exemple) ... utiliser un pipe (attention à Windows) ?

## Plugin IDA
* colorer les lignes teintées
* GDT par défaut
* fichier de conf par défaut externe

## Global
* tester sous Windows ?
* webservice pour permettre au plugin de marcher avec un bincat distant
* spécifier les sections de data et leurs adresses (physiques/virtuelles) pour permettre à bincat de les lire dans le binaire direct
