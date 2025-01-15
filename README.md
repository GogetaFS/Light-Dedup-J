# GogetaFS atop PM Code Base

This repository contains the code base for GogetaFS atop PM. The code is based on [Light-Dedup](https://github.com/Light-Dedup/Light-Dedup). The artifact evaluation steps can be obtained from [GogetaFS-AE](https://github.com/GogetaFS/GogetaFS-AE). We now introduce the code base and the branches corresponding to the paper.

- [GogetaFS atop PM Code Base](#gogetafs-atop-pm-code-base)
  - [Code Organization](#code-organization)
  - [Branches Corresponding to the Paper](#branches-corresponding-to-the-paper)

## Code Organization

Atop NOVA file system, we mainly modify files below for GogetaFS.

- `table.c/table.h`: the basic deduplication logic implementation. `light_dedup_incr_ref_continuous` is the core function to deduplicate data block(s). 

- `bbuild.c`: we intercept `nova_set_file_bm` for recovering GogetaFS deduplication service from crash.

- `entry.c/entry.h`: manipulate single entry in the GLT.

- `rhashtable-ext.c/rhashtable-ext.h`: preallocate rhashtable to improve recovery performance, the same as Light-Dedup.

- `fingerprint.h`: define the fingerprinting algorithm (i.e., wyhash).

- `wyhash.h`: the wyhash implementation.

- `xatable.c/xatable.h`: the implementation of multi-core xarray for concurrent recovery. 

 
## Branches Corresponding to the Paper

- *light-fs-dedup*: GogetaFS with secure mode.

- *light-fs-dedup-64bit-fp*: GogetaFS with non-secure mode (default).

- *light-fs-dedup-64bit-fp-failure*: GogetaFS with failure recovery.


- *light-fs-dedup-disable-dedup*: GogetaFS with deduplication disabled.

- *light-fs-dedup-super*: GogetaFS with super-fingerprint (SFP).

- *light-fs-dedup-regulate*: GogetaFS with regulated memory (Figure 8b with mem>0 and Figure 8d with mem=0).

- *light-fs-dedup-pm-table*: GogetaHybrid (Figure 8c).
 
- *light-fs-dedup-pm-table-persistence*: Light-Dedup with memory regulation (corresponding to Light-Dedup in Figure 12).

- *light-fs-dedup-pm-all*: GogetaSHT (Figure 8e), which is GogetaFS using static hash table for all-in-PM organization.

- *light-fs-dedup-pm-all-persistence*: SHT, GogetaSHT without LFP entries.

- *nova-pipe*: NOVA file system, the baseline.

- *nova-pipe-failure*: NOVA file system with failure recovery.

- *denova*: DeNova file system.

- *denova-non-crypto*: DeNova without using crypto hash.

- *nova-pipe-dedup*: Light-Dedup file system.

- *nova-pipe-dedup-failure*: Light-Dedup file system with failure recovery.