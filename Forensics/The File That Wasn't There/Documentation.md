CTF Walkthrough — File That Wasn't There

# 1. Challenge Overview

Challenge title: File That Wasn't There
Flag format: `cveplay{...}`
Initial file: `The File That Wasn't There.zip`

The ZIP archive does not directly contain the individual clue files. It contains:

challenge/
└── evidence.img

The other files used during the investigation—such as `manifest.json`, `report.txt`, `hashes.txt`, `notes/derived.txt`, and the fragment files—are recovered from data inside `evidence.img`.

The central idea of the challenge is that an important file was deleted, but information about it survived in:

* the ext4 filesystem metadata
* a SQLite backup index
* extended attributes
* deleted/unallocated filesystem data
* a recovered TAR archive containing the challenge instructions


# 2. Extract the ZIP

After downloading the challenge ZIP on Kali:

bash: 
      unzip "The File That Wasn't There.zip"

Check the extracted directory:

bash: 
      find . -maxdepth 3 -type f -print

The important file is:

challenge/evidence.img

Move into the challenge directory:

bash:
      cd challenge

# 3. Identify the Disk Image

Run:

bash:
      file evidence.img

The result identifies it as an **ext4 filesystem image**.

The image also reports that journal recovery is needed, so the evidence should be treated carefully and mounted read-only.


# 4. Inspect the Filesystem

Create a mount point:

bash:
      sudo mkdir -p /mnt/ctf

Mount the image read-only:

bash:
      sudo mount -o ro,loop,noload evidence.img /mnt/ctf

The options mean:

* ro — read-only
* loop — mount the image as a loop device
* noload — don't replay the filesystem journal

Check the filesystem:

bash:
      ls -lah /mnt/ctf


# 5. Investigate the Home Directory

The interesting user directory is:

/home/analyst/

List its files:

bash:
find /mnt/ctf/home/analyst -type f -printf '%p\n'

Also include hidden directories:

bash:
      ls -la /mnt/ctf/home/analyst

One particularly interesting location is:

/home/analyst/Documents/.staging/.fragmenters/

Investigate it with:

bash:
      find /mnt/ctf/home/analyst/Documents/.staging/.fragmenters \
      -type f -exec file {} \;

and:

bash:
      find /mnt/ctf/home/analyst/Documents/.staging/.fragmenters \
      -type f -ls

The hidden `.staging` and `.fragmenters` directories are clues that something was staged and subsequently removed.


# 6. Look for Deleted Files

Use The Sleuth Kit:

bash:
      fls -r -d evidence.img

The `-r` option recursively examines the filesystem and `-d` shows deleted entries.

One important deleted entry is:
home/analyst/Documents/.staging/atlas_sync_bundle.tar

The associated inode is:
37
This is the key deleted file.

The challenge title, **"File That Wasn't There"**, starts making sense here: the file is no longer present normally, but filesystem remnants still exist.


# 7. Inspect the Deleted Inode

Use:
bash:
      istat evidence.img 37

This provides metadata associated with inode 37.

The useful information includes:
* inode number
* timestamps
* file size
* extent/block information
* deletion information

The inode number is:
37

The original filename is:
atlas_sync_bundle.tar


# 8. Try Normal Inode Recovery

An obvious first attempt is:

bash:
      icat evidence.img 37 > atlas_sync_bundle.tar

Then:

bash:
      ls -lh atlas_sync_bundle.tar

and:

bash:
      file atlas_sync_bundle.tar

Finally:

bash:
      tar -tf atlas_sync_bundle.tar

In this challenge, the recovered inode data does not give us a usable TAR archive. `tar -tf` produces no useful entries.
This is an important forensic lesson:
A deleted inode does not necessarily mean the original file contents are still recoverable directly through the inode.
Therefore, the next step is to investigate unallocated filesystem data.


# 9. Search the Raw Image for TAR Headers

A TAR archive contains the ASCII signature:
ustar

Search the raw image:

bash:
      grep -aob 'ustar' evidence.img

This produces offsets where TAR headers occur.
The important offsets include:

29750784
29941760
29942784
29943808
29944832
29945856
29946880
30145024
30343168
30542848
30936576
31134208
31213568

A TAR header is 512 bytes long, and the `ustar` signature occurs at offset `257` within the header.

Therefore, if:
ustar offset = 29942017
the TAR header starts at:
29942017 - 257

This allowed the deleted TAR entries to be identified directly inside the raw filesystem image.


# 10. Inspect a TAR Header

For example:

bash:
      dd if=evidence.img bs=1 skip=29945856 count=512 2>/dev/null | od -Ax -tx1z

The beginning contains:
notes/derived.txt

and around offset `0x101` is:
ustar

This confirms that the data at this location is a TAR header.
The TAR header also contains the file size.

For `notes/derived.txt`, the size is:
325 bytes


# 11. Recover the TAR Entries

The discovered TAR headers correspond to files such as:

manifest.json
report.txt
notes/timeline.csv
hashes.txt
notes/derived.txt
notes/quiet.txt
fragments/part_00.bin
fragments/part_01.bin
fragments/part_02.bin
fragments/part_03.bin
fragments/part_04.bin
fragments/part_05.bin
evidence.bin

A useful approach is to create a recovery directory:

bash:
      mkdir -p recovered

Then carve the individual TAR entries from their header offsets.
For example, to recover `notes/derived.txt`:

bash:
      dd if=evidence.img \ bs=1 \ skip=$((29945856+512)) \ count=325 \ of=recovered_derived.txt

The same technique can be used for the other TAR entries once their header offsets and sizes are known.

The resulting logical structure is:

recovered/
├── manifest.json
├── report.txt
├── hashes.txt
├── notes/
│   ├── timeline.csv
│   ├── derived.txt
│   └── quiet.txt
└── fragments/
    ├── part_00.bin
    ├── part_01.bin
    ├── part_02.bin
    ├── part_03.bin
    ├── part_04.bin
    └── part_05.bin


# 12. Read `manifest.json`

Inspect it:

bash:
      cat recovered/manifest.json

The important portion is:

```json
{
  "bundle_id":"north-signal",
  "derive":"flag = digest_prefix + sha256(original_name|inode|first_extent|created_utc|trace_tag|nonce)[:24]",
  "members":[
    "manifest.json",
    "report.txt",
    "notes/timeline.csv",
    "hashes.txt",
    "notes/derived.txt",
    "fragments/part_00.bin"
  ],
  "nonce":"a7c0280bfb1a85db"
}
```
This is the most important clue in the entire challenge.
The formula is:

flag = digest_prefix + sha256(original_name | inode | first_extent | created_utc | trace_tag | nonce)[:24]

The `[:24]` explicitly tells us to take the first 24 hexadecimal characters of the calculated SHA-256 digest.
The manifest also gives us:

nonce = a7c0280bfb1a85db


# 13. Read `report.txt`

bash:
      cat recovered/report.txt

It says:
```
The bundle was prepared off-network and staged locally.
The manifest nonce is a7c0280bfb1a85db.
The archive name on disk was not the final name.
```

The last sentence is important:
```
The archive name on disk was not the final name.
```
This reinforces why the deleted inode's original filename must be recovered rather than simply trusting a visible filename.


# 14. Read the Timeline

bash:
      cat recovered/notes/timeline.csv

The timeline contains:
```
utc,action
2026-08-11T09:41:17Z,staged
2026-08-11T09:41:25Z,linked
2026-08-11T09:41:31Z,rotated
2026-08-11T09:41:41Z,annotated
2026-08-11T09:47:33Z,unlinked
```

The important creation/staging timestamp is:
```
2026-08-11T09:41:17Z
```
The final `unlinked` event also explains why the file disappeared.


# 15. Read `notes/derived.txt`

bash:
      cat recovered/notes/derived.txt

It states that the final token requires:
- original filename
- inode number
- first physical extent
- creation timestamp from the application index
- user.trace xattr
- manifest nonce

This tells us exactly which pieces of metadata need to be collected.


# 16. Investigate the Backup SQLite Database

Inside the mounted image there is:

home/analyst/.local/share/backup_index.sqlite

Copy it out:

bash:
      cp /mnt/ctf/home/analyst/.local/share/backup_index.sqlite .

Identify it:

bash:
      file backup_index.sqlite

Then open it:

bash:
      sqlite3 backup_index.sqlite

Inside SQLite:
              .tables

The database contains:

- artifacts
- operations

Inspect the schema:
                    .schema artifacts
                    .schema operations

Display the artifacts:
sql
    .headers on
    .mode column
    SELECT * FROM artifacts;

The relevant record is:

logical_name:
atlas_sync_bundle.tar

inode:
37

size:
1073152

sha256:
25e14c56787938cec8510abf96dd10ba1c5eea478e49e43a55e49596b69503f0

first_extent:
2025

trace_tag:
trace-ee4b583b

created_utc:
2026-08-11T09:41:17Z

deleted_utc:
2026-08-11T09:47:33Z


The database therefore gives us the important application metadata.


# 17. Identify the Correct Database Record

There are several records in the database, including decoys.
Search specifically for the deleted archive:

sql
    SELECT *
    FROM artifacts
    WHERE logical_name = 'atlas_sync_bundle.tar';

This avoids accidentally using one of the decoy entries.

The correct record has:
inode = 37

which matches the deleted inode discovered with `fls`.

It also has:
trace_tag = trace-ee4b583b

and:
created_utc = 2026-08-11T09:41:17Z


# 18. Check the Operations Table

Inside SQLite:

sql
      SELECT * FROM operations;

The interesting sequence is:

create
link
rename
unlink

The relevant paths include:

/home/analyst/Documents/atlas_sync_bundle.tar
/tmp/.cache/atlas_sync_bundle.2026.tar
/home/analyst/Downloads/atlas_sync_bundle.2026.tar

This explains the clue:
The archive name on disk was not the final name.
The archive was staged, linked, renamed/rotated, and eventually unlinked.


# 19. Recover the Trace Tag

The challenge specifically mentions the extended attribute:
user.trace

The relevant value is:
trace-ee4b583b

This agrees with the SQLite record:
trace_tag = trace-ee4b583b

This cross-check is useful because it confirms that the database record and the deleted inode refer to the same artifact.


# 20. Collect the Values for the Hash

At this point the values are:

original_name = atlas_sync_bundle.tar
inode = 37
first_extent = 2025
created_utc = 2026-08-11T09:41:17Z
trace_tag = trace-ee4b583b
nonce = a7c0280bfb1a85db

Construct the exact string:

atlas_sync_bundle.tar|37|2025|2026-08-11T09:41:17Z|trace-ee4b583b|a7c0280bfb1a85db

**Do not add spaces or change the separators.**


# 21. Calculate the SHA-256

bash:
      printf '%s' \ 'atlas_sync_bundle.tar|37|2025|2026-08-11T09:41:17Z|trace-ee4b583b|a7c0280bfb1a85db' \ | sha256sum

The SHA-256 digest is:
ab9821e86991a9cfa6262c4d8715052f382edae26bdc1aef98a732536340a292

The manifest says:
sha256(...)[:24]

Therefore take:
ab9821e86991a9cfa6262c4d


# 22. Determine the Digest Prefix

The SQLite record contains the bundle SHA-256:
25e14c56787938cec8510abf96dd10ba1c5eea478e49e43a55e49596b69503f0

The challenge's `digest_prefix` is:
25e14c56

That is the first eight hexadecimal characters of the stored bundle digest.

The manifest then tells us to concatenate:
digest_prefix + sha256(...)[:24]


# 23. Construct the Flag

Digest prefix:
25e14c56

First 24 characters of derived SHA-256:
ab9821e86991a9cfa6262c4d

Concatenate:
25e14c56ab9821e86991a9cfa6262c4d

Apply the required flag format:
cveplay{25e14c56ab9821e86991a9cfa6262c4d}


# 24. Final Investigation Chain

The entire challenge can be summarized as:

The File That Wasn't There.zip
             │
             ▼
      challenge/evidence.img
             │
             ▼
          ext4 image
             │
             ├── hidden/staging directories
             │
             ├── deleted inode 37
             │       │
             │       └── atlas_sync_bundle.tar
             │
             ├── backup_index.sqlite
             │       │
             │       ├── inode = 37
             │       ├── first_extent = 2025
             │       ├── created_utc = 2026-08-11T09:41:17Z
             │       ├── trace_tag = trace-ee4b583b
             │       └── SHA-256 = 25e14c56...
             │
             └── deleted/unallocated TAR data
                     │
                     ├── manifest.json
                     │       └── nonce = a7c0280bfb1a85db
                     │
                     ├── report.txt
                     ├── timeline.csv
                     ├── hashes.txt
                     └── derived.txt
                              │
                              ▼
                sha256(original_name|inode|
                first_extent|created_utc|
                trace_tag|nonce)[:24]
                              │
                              ▼
                   ab9821e86991a9cfa6262c4d
                              │
                              ▼
                   digest_prefix = 25e14c56
                              │
                              ▼
          cveplay{25e14c56ab9821e86991a9cfa6262c4d}
          

# 25. Useful Command Summary

The important commands are:

bash:
unzip "The File That Wasn't There.zip"
cd challenge
      
file evidence.img

sudo mkdir -p /mnt/ctf
sudo mount -o ro,loop,noload evidence.img /mnt/ctf

find /mnt/ctf/home/analyst -type f -printf '%p\n'

find /mnt/ctf/home/analyst/Documents/.staging \ -type f -exec file {} \;

fls -r -d evidence.img

istat evidence.img 37

icat evidence.img 37 > atlas_sync_bundle.tar

file atlas_sync_bundle.tar
tar -tf atlas_sync_bundle.tar

grep -aob 'ustar' evidence.img

cp /mnt/ctf/home/analyst/.local/share/backup_index.sqlite .

sqlite3 backup_index.sqlite

Inside SQLite:

sql
.tables
.schema artifacts
.schema operations
.headers on
.mode column
SELECT * FROM artifacts;
SELECT * FROM operations;

Then:

bash:
cat recovered/manifest.json
cat recovered/report.txt
cat recovered/notes/timeline.csv
cat recovered/notes/derived.txt
cat recovered/hashes.txt

Finally:

bash:
printf '%s' \
'atlas_sync_bundle.tar|37|2025|2026-08-11T09:41:17Z|trace-ee4b583b|a7c0280bfb1a85db' \ | sha256sum


## Important Forensic Lessons

1. A deleted file can still leave its **inode and metadata** behind.
2. A failed `icat` recovery does not mean the investigation is over.
3. Deleted data can survive in **unallocated space**.
4. `ustar` is a useful signature for locating TAR archives in raw data.
5. SQLite databases can preserve application-level history even after the corresponding filesystem object is deleted.
6. Hidden directories such as `.staging` and `.fragmenters` deserve attention.
7. The exact input string to a cryptographic hash matters: filename, separators, timestamps, capitalization, and ordering must all be preserved exactly.
