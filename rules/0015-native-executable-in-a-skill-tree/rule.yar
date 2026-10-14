rule as_0015_native_executable_in_a_skill_tree {
  meta:
    id          = 15
    title       = "A skill that ships a native executable"
    tier        = 1
    category    = "threat"
    severity    = "critical"
    class       = 1
    kinds       = "Skill"
    status      = "probation"
    plain       = "This skill carries a program nobody can read, and the agent can run it."
    phrase      = "carries a program nobody can read"
    description = "A file inside a skill directory whose first bytes are a native executable header: Mach-O, ELF, a PE image, or the Mach-O a `.node` addon is. A skill is instructions plus, at most, scripts; the format has no place for a compiled binary, and the agent puts a skill's `bin` on its own PATH. GlassWorm shipped a Zig dropper this way and the fake extension campaign the same, because a binary is the one thing in a skill tree that no review reads and no diff shows. The Rule reads the header the Surface Adapter classified the file by, so it lands on the file itself and names it. A shell or Python script stays silent, an image stays silent, and a SKILL.md that merely talks about a binary stays silent, because prose is not a header."
    references  = "https://www.aikido.dev/blog/glassworm-zig-dropper-infects-every-ide-on-your-machine https://thehackernews.com/2026/04/researchers-uncover-73-fake-vs-code.html https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $mach_o_32_be = { fe ed fa ce }
    $mach_o_64_be = { fe ed fa cf }
    $mach_o_32_le = { ce fa ed fe }
    $mach_o_64_le = { cf fa ed fe }
    $mach_o_fat   = { ca fe ba be }
    $elf          = { 7f 45 4c 46 }
    $pe           = { 4d 5a }

  condition:
    item.kind == "Skill"
    and item.file_type == "executable"
    and for any of them : ( $ at 0 )
}
