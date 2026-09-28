rule as_0585_payload_file_in_a_skill_or_plugin_tree {
  meta:
    id          = 585
    title       = "A file in a skill or plugin that a reviewer cannot read"
    tier        = 2
    weight      = 2
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill,Plugin"
    status      = "stable"
    plain       = "This carries a packed or compiled file, which is where a payload hides from anyone reading the source."
    description = "An archive, an office document or interpreter bytecode inside a skill tree, or a native executable inside a plugin tree anywhere other than its `bin` directory. Trail of Bits found skills whose payload sat in a `.docx`, a `.pyc` and a zip, referenced from SKILL.md, precisely because a scanner and a reviewer both read the Markdown and stop. The Heuristic decides on the file type alone: it does not ask whether SKILL.md or a script names the file, so a packed file nothing points at reads the same as one that is unpacked on load. This is not a Rule because the legitimate uses are real: the vendor's own document skills ship office templates, and running a skill script writes bytecode, so a `__pycache__` path is excluded here rather than weighed. A native executable in a skill tree is Rule 0015 and is not weighed twice; the plugin half is here because a plugin's `bin` is a documented place for a compiled helper and the rest of the tree is not."
    references  = "https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ https://www.aikido.dev/blog/glassworm-zig-dropper-infects-every-ide-on-your-machine docs/research/attack-catalogue.md#3"
    sensitive   = false

  // File type alone, by the decision of 2026-09-28. If precision ever
  // needs it, a `named_by_a_sibling` fact computed by the adapter (the file
  // is named by SKILL.md or a script of the same tree) is the future work that
  // would narrow the skill half to the shape Trail of Bits described.
  condition:
    (item.kind == "Skill"
      and (item.file_type == "archive" or item.file_type == "office" or item.file_type == "bytecode")
      and not (item.file contains "__pycache__/"))
    or (item.kind == "Plugin"
      and item.file_type == "executable"
      and not (item.file startswith "bin/"))
}
