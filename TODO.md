## Ocaml
* Utiliser au moins TROIS caractères pour toutes les variables (oui, si, vraiment.)

* regrouper les suites d'instruction décodées en basic blocks (pluôt
qu'un état par instruction x86) (ou pas, à discuter)
* supprimer les maj de flags entre deux instructions pour ceux qui sont set/undef sans avoir été testés


* sortir les informations nécessaires à l'affichage de la teinte
* gérer les questions "synchrones" avec l'interface IDA pour quand il y a une décision à prendre (trop de branches par exemple) ... utiliser un pipe (attention à Windows) ?
* gérer des chemins UTF-8 dans le .ini ?
* tests QEMU : gérer le `printf` => directive magique ?
* vérifier popf/pushf (surtout les privilèges etc)
* écrire un programme de test : binaire => statements (à la metasm-shell)
* à clarifier : pointer n'est pas un pointer mais une valeur
* pouvoir spécifier la valeur d'un registre ou adress mémoire à une adresse différente de celle de début
* gérer l'ordre des initialisation mémoires dans le .ini pour pouvoir écraser certaines parties déjà initialisées
* numeric log levels (not just verbose)
* log categories (mem, vectors, etc.)

## Plugin IDA
* gérer des traces multiples à la même adresse (afficher tous les états, pas juste celui marqué "final")
* importer les valeurs concrètes depuis le debugger (mémoire et registres)
* fenetre de registre jolie (couleur pour la teinte)
* colorer les lignes teintées
* désactiver les contrôles "start address" et "stop address" lorsqu'une configuration a été chargée par l'utilisateur, ou modifiée

## Global
* faire marcher `bincat` sous windows ?
* spécifier les sections de data et leurs adresses (physiques/virtuelles) pour permettre à bincat de les lire dans le binaire direct
* gérer des diffs de mémoire seulement ? (bcp d'instructions ne touchent pas la mémoire, ça éviterait de perdre du temps à tout réécrire.)


