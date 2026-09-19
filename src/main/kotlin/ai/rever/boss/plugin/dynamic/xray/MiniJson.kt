package ai.rever.boss.plugin.dynamic.xray

/**
 * A small JSON reader for `plugin.json`.
 *
 * Not `kotlinx.serialization`: a plugin JAR carries only its own classes and borrows everything else
 * from the host, and a scanner that stops working when the host changes which JSON library it exposes is
 * a scanner that fails exactly when someone is trying to use it. The input is a stranger's file, so it is
 * bounded on size and on depth and never throws anything but [JsonException].
 *
 * Values come back as `Map<String, Any?>`, `List<Any?>`, `String`, `Double`, `Boolean` and `null`.
 */
internal object MiniJson {
    private const val MAX_CHARS = 1_000_000
    private const val MAX_DEPTH = 32

    fun parse(text: String): Any? {
        if (text.length > MAX_CHARS) throw JsonException("document larger than $MAX_CHARS characters")
        val reader = Reader(text)
        val value = reader.value(0)
        reader.skipWhitespace()
        if (!reader.atEnd()) throw JsonException("unexpected text after the document")
        return value
    }

    private class Reader(
        private val s: String,
    ) {
        private var i = 0

        fun atEnd() = i >= s.length

        fun skipWhitespace() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw JsonException("nested deeper than $MAX_DEPTH")
            skipWhitespace()
            if (atEnd()) throw JsonException("unexpected end")
            return when (val c = s[i]) {
                '{' -> obj(depth)
                '[' -> array(depth)
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) number() else throw JsonException("unexpected character")
            }
        }

        private fun literal(
            word: String,
            result: Any?,
        ): Any? {
            if (!s.startsWith(word, i)) throw JsonException("unexpected literal")
            i += word.length
            return result
        }

        private fun number(): Double {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            return s.substring(start, i).toDoubleOrNull() ?: throw JsonException("malformed number")
        }

        private fun obj(depth: Int): Map<String, Any?> {
            i++ // {
            val out = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek() == '}') {
                i++
                return out
            }
            while (true) {
                skipWhitespace()
                if (peek() != '"') throw JsonException("object key must be a string")
                val key = string()
                skipWhitespace()
                if (peek() != ':') throw JsonException("missing ':'")
                i++
                out[key] = value(depth + 1)
                skipWhitespace()
                when (peek()) {
                    ',' -> i++
                    '}' -> {
                        i++
                        return out
                    }
                    else -> throw JsonException("expected ',' or '}'")
                }
            }
        }

        private fun array(depth: Int): List<Any?> {
            i++ // [
            val out = ArrayList<Any?>()
            skipWhitespace()
            if (peek() == ']') {
                i++
                return out
            }
            while (true) {
                out += value(depth + 1)
                skipWhitespace()
                when (peek()) {
                    ',' -> i++
                    ']' -> {
                        i++
                        return out
                    }
                    else -> throw JsonException("expected ',' or ']'")
                }
            }
        }

        private fun peek(): Char = if (i < s.length) s[i] else throw JsonException("unexpected end")

        private fun string(): String {
            i++ // opening quote
            val sb = StringBuilder()
            while (true) {
                val c = peek()
                i++
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> sb.append(escape())
                    c < ' ' -> throw JsonException("control character in string")
                    else -> sb.append(c)
                }
            }
        }

        private fun escape(): Char {
            val c = peek()
            i++
            return when (c) {
                '"', '\\', '/' -> c
                'b' -> '\b'
                'f' -> 0x0c.toChar()
                'n' -> '\n'
                'r' -> '\r'
                't' -> '\t'
                'u' -> {
                    if (i + 4 > s.length) throw JsonException("truncated \\u escape")
                    val code = s.substring(i, i + 4).toIntOrNull(HEX) ?: throw JsonException("malformed \\u escape")
                    i += 4
                    code.toChar()
                }
                else -> throw JsonException("unknown escape")
            }
        }
    }

    private const val HEX = 16
}

internal class JsonException(
    reason: String,
) : Exception(reason)

@Suppress("UNCHECKED_CAST")
internal fun Any?.asObject(): Map<String, Any?>? = this as? Map<String, Any?>

internal fun Any?.asStringList(): List<String> = (this as? List<*>)?.filterIsInstance<String>().orEmpty()
