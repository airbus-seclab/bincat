## Ocaml
* Utiliser au moins TROIS caractères pour toutes les variables (oui, si, vraiment.)

* regrouper les suites d'instruction décodées en basic blocks (pluôt
qu'un état par instruction x86) (ou pas, à discuter)
* supprimer les maj de flags entre deux instructions pour ceux qui sont set/undef sans avoir été testés
* changer la modélisation des flags gérés en "if" pour qu'ils puissent etre tainted
* gérer les questions "synchrones" avec l'interface IDA pour quand il y a une décision à prendre (trop de branches par exemple) ... utiliser un pipe (attention à Windows) ?
* gérer des chemins UTF-8 dans le .ini ?
* tests QEMU : gérer le `printf` => directive magique ?
* vérifier popf/pushf (surtout les privilèges etc)
* écrire un programme de test : binaire => statements (à la metasm-shell)
* à clarifier : pointer n'est pas un pointer mais une valeur
* gérer l'ordre des initialisation mémoires dans le .ini pour pouvoir écraser certaines parties déjà initialisées
* log categories (mem, vectors, etc.)

Bugs:
* autoriser les '?' dans les noms de fonctions

Hard :
* use a shared data structure to store memory only once for all states

## Plugin IDA
* importer les valeurs concrètes depuis le debugger (mémoire et registres)
* installer windows

## Global
* faire marcher `bincat` sous windows ?
* gérer des diffs de mémoire seulement ? (bcp d'instructions ne touchent pas la mémoire, ça éviterait de perdre du temps à tout réécrire.)
* GDB stub pour l'accès à la mémoire (utile pour les processus qui tournent mais aussi pour les binaires compliqués (relocs etc.))
* versionner le .ini

