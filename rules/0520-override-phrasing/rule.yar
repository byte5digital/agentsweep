rule as_0520_override_phrasing {
  meta:
    id          = 520
    title       = "Text that tells the agent to drop the instructions it already has"
    tier        = 2
    weight      = 3
    category    = "threat"
    severity    = "high"
    class       = 4
    kinds       = "InstructionFile,Skill,Subagent,Plugin,Workflow"
    status      = "stable"
    reviewer_directed = true
    plain       = "This file tells the agent to throw away the instructions it was given and take new ones from here."
    description = "An order to ignore, forget or override what came before, a claim that the text supersedes the instructions already in force, a new identity handed to the reader, or a mode said to be engaged. Prompt injection lives on these sentences: the file is read as instructions, so one line of it can put the rest of the session under the file's author. Telling the agent to ignore a build directory, or saying it is now ready for the next step, carries none of this. A phrase inside quotation marks or a code span is named rather than given, which is how guidance against prompt injection quotes the sentences it warns about, so it does not count; the same phrase unquoted anywhere in the file still does. Reviewer directed, because whatever model is later asked whether the file is safe reads the same sentence."
    references  = "https://www.hiddenlayer.com/research/how-hidden-prompt-injections-can-hijack-ai-code-assistants-like-cursor https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ docs/research/attack-catalogue.md#3"
    sensitive   = false

  strings:
    $ignore_previous = /\b(ignore|disregard|forget|discard|override)\b[^\n]{0,40}\b(previous|prior|earlier|preceding|above|foregoing|system)\b[^\n]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines|context)\b/ nocase
    $supersedes      = /\b(supersede|supersedes|superseded|replace|replaces|override|overrides|takes precedence over|take precedence over)\b[^\n]{0,40}\b(previous|prior|earlier|any other|all other|the system|the user)\b[^\n]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines)\b/ nocase
    $you_are_now     = /\byou are now\b[^\n]{0,40}\b(an|a|the)\b[^\n]{0,30}\b(assistant|agent|ai|model|system|administrator|admin|root|operator|unrestricted|uncensored|unfiltered)\b/ nocase
    $mode_engaged    = /\b(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n]{0,30}\b(enabled|engaged|activated|active|on)\b/ nocase
    $in_mode         = /\b(you are|the assistant is|the agent is|the model is)[ \t]+(now[ \t]+)?in[ \t]+(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b/ nocase

    // The same five phrases where they are named rather than given: inside
    // straight or curly double quotes, inside a code span, or with single
    // quotes directly around the phrase. A single quote is held to the
    // phrase's own edges because an apostrophe elsewhere on the line would
    // otherwise open a quotation that is not there. Inside a quotation the
    // gaps of a phrase never cross a double quote or a backtick, so the
    // phrase sits within one quotation.
    $q_ignore_previous = /(("|\xE2\x80\x9C)[^\n"`\xE2]{0,60}\b(ignore|disregard|forget|discard|override)\b[^\n"`]{0,40}\b(previous|prior|earlier|preceding|above|foregoing|system)\b[^\n"`]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines|context)\b[^\n"`\xE2]{0,60}("|\xE2\x80\x9D)|`[^\n`]{0,60}\b(ignore|disregard|forget|discard|override)\b[^\n"`]{0,40}\b(previous|prior|earlier|preceding|above|foregoing|system)\b[^\n"`]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines|context)\b[^\n`]{0,60}`|('|\xE2\x80\x98)(ignore|disregard|forget|discard|override)\b[^\n"`]{0,40}\b(previous|prior|earlier|preceding|above|foregoing|system)\b[^\n"`]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines|context)('|\xE2\x80\x99))/ nocase
    $q_supersedes      = /(("|\xE2\x80\x9C)[^\n"`\xE2]{0,60}\b(supersede|supersedes|superseded|replace|replaces|override|overrides|takes precedence over|take precedence over)\b[^\n"`]{0,40}\b(previous|prior|earlier|any other|all other|the system|the user)\b[^\n"`]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines)\b[^\n"`\xE2]{0,60}("|\xE2\x80\x9D)|`[^\n`]{0,60}\b(supersede|supersedes|superseded|replace|replaces|override|overrides|takes precedence over|take precedence over)\b[^\n"`]{0,40}\b(previous|prior|earlier|any other|all other|the system|the user)\b[^\n"`]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines)\b[^\n`]{0,60}`|('|\xE2\x80\x98)(supersede|supersedes|superseded|replace|replaces|override|overrides|takes precedence over|take precedence over)\b[^\n"`]{0,40}\b(previous|prior|earlier|any other|all other|the system|the user)\b[^\n"`]{0,30}\b(instruction|instructions|prompt|prompts|rule|rules|guideline|guidelines)('|\xE2\x80\x99))/ nocase
    $q_you_are_now     = /(("|\xE2\x80\x9C)[^\n"`\xE2]{0,60}\byou are now\b[^\n"`]{0,40}\b(an|a|the)\b[^\n"`]{0,30}\b(assistant|agent|ai|model|system|administrator|admin|root|operator|unrestricted|uncensored|unfiltered)\b[^\n"`\xE2]{0,60}("|\xE2\x80\x9D)|`[^\n`]{0,60}\byou are now\b[^\n"`]{0,40}\b(an|a|the)\b[^\n"`]{0,30}\b(assistant|agent|ai|model|system|administrator|admin|root|operator|unrestricted|uncensored|unfiltered)\b[^\n`]{0,60}`|('|\xE2\x80\x98)you are now\b[^\n"`]{0,40}\b(an|a|the)\b[^\n"`]{0,30}\b(assistant|agent|ai|model|system|administrator|admin|root|operator|unrestricted|uncensored|unfiltered)('|\xE2\x80\x99))/ nocase
    $q_mode_engaged    = /(("|\xE2\x80\x9C)[^\n"`\xE2]{0,60}\b(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n"`]{0,30}\b(enabled|engaged|activated|active|on)\b[^\n"`\xE2]{0,60}("|\xE2\x80\x9D)|`[^\n`]{0,60}\b(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n"`]{0,30}\b(enabled|engaged|activated|active|on)\b[^\n`]{0,60}`|('|\xE2\x80\x98)(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n"`]{0,30}\b(enabled|engaged|activated|active|on)('|\xE2\x80\x99))/ nocase
    $q_in_mode         = /(("|\xE2\x80\x9C)[^\n"`\xE2]{0,60}\b(you are|the assistant is|the agent is|the model is)[ \t]+(now[ \t]+)?in[ \t]+(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n"`\xE2]{0,60}("|\xE2\x80\x9D)|`[^\n`]{0,60}\b(you are|the assistant is|the agent is|the model is)[ \t]+(now[ \t]+)?in[ \t]+(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode\b[^\n`]{0,60}`|('|\xE2\x80\x98)(you are|the assistant is|the agent is|the model is)[ \t]+(now[ \t]+)?in[ \t]+(developer|debug|god|admin|unrestricted|jailbreak)[ \t]+mode('|\xE2\x80\x99))/ nocase

  // A phrase counts when at least one of its occurrences starts outside
  // every quotation of the same phrase.
  condition:
    item.file_type == "text"
    and (
      (for any i in (1..#ignore_previous) : (
        not for any j in (1..#q_ignore_previous) : (
          @q_ignore_previous[j] <= @ignore_previous[i]
          and @ignore_previous[i] < @q_ignore_previous[j] + !q_ignore_previous[j])))
      or (for any i in (1..#supersedes) : (
        not for any j in (1..#q_supersedes) : (
          @q_supersedes[j] <= @supersedes[i]
          and @supersedes[i] < @q_supersedes[j] + !q_supersedes[j])))
      or (for any i in (1..#you_are_now) : (
        not for any j in (1..#q_you_are_now) : (
          @q_you_are_now[j] <= @you_are_now[i]
          and @you_are_now[i] < @q_you_are_now[j] + !q_you_are_now[j])))
      or (for any i in (1..#mode_engaged) : (
        not for any j in (1..#q_mode_engaged) : (
          @q_mode_engaged[j] <= @mode_engaged[i]
          and @mode_engaged[i] < @q_mode_engaged[j] + !q_mode_engaged[j])))
      or (for any i in (1..#in_mode) : (
        not for any j in (1..#q_in_mode) : (
          @q_in_mode[j] <= @in_mode[i]
          and @in_mode[i] < @q_in_mode[j] + !q_in_mode[j])))
    )
}
