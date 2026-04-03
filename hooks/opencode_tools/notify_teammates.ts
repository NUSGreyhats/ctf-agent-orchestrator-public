import { tool } from "@opencode-ai/plugin"

export default tool({
    description:
        "Broadcast a validated breakthrough to all teammates. " +
        "Only call for confirmed, significant findings.",
    args: {
        message: tool.schema
            .string()
            .describe("The breakthrough finding to broadcast"),
    },
    async execute(args, ctx) {
        const fs = await import("fs")
        const path = await import("path")
        const queueFile = path.join(
            ctx.directory,
            "_shared",
            ".notify_queue",
        )
        // Ensure _shared directory exists
        const dir = path.dirname(queueFile)
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true })
        }
        fs.appendFileSync(
            queueFile,
            `${Date.now()}|${args.message}\n`,
        )
        return "Broadcast queued for teammates"
    },
})
