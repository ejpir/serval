//! Audit top-level `pub const` ownership outside `serval-core`.
//!
//! The audit is intentionally narrower than "every non-core `pub const` is wrong".
//! It focuses on two high-signal cases:
//! 1. non-core public aliases that resolve back into `serval-core`
//! 2. non-core public constants with duplicate normalized semantics across files

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("pub_const_audit_options");

const max_arg_count: u8 = 8;
const max_scanned_files: u32 = 4096;
const max_alias_resolution_depth: u8 = 16;
const max_reported_members_per_group: u8 = 12;
const max_source_file_size_bytes: u32 = 2 * 1024 * 1024;
const min_candidate_external_modules: u8 = 2;

const RunMode = enum {
    strict,
    report_only,
};

const CliConfig = struct {
    repo_root: []const u8 = build_options.repo_root,
    mode: RunMode = .strict,
};

const PubConstKind = enum {
    mod_reexport,
    core_alias,
    type_definition,
    literal,
    symbolic_expr,
};

const AliasDecl = struct {
    name: []const u8,
    raw_expr: []const u8,
    resolved_expr: ?[]const u8 = null,
};

const PendingPubConst = struct {
    symbol: []const u8,
    line: u32,
    raw_expr: []const u8,
};

const ModuleImport = struct {
    alias: []const u8,
    target_module: []const u8,
};

const SourceFile = struct {
    module: []const u8,
    rel_path: []const u8,
    source: []const u8,
    module_imports: []const ModuleImport,
};

const PubConstRecord = struct {
    module: []const u8,
    rel_path: []const u8,
    basename: []const u8,
    symbol: []const u8,
    line: u32,
    raw_expr: []const u8,
    resolved_expr: []const u8,
    kind: PubConstKind,
};

const FindingGroup = struct {
    key: []const u8,
    members: []const PubConstRecord,
};

const AuditReport = struct {
    scanned_file_count: u32,
    pub_const_count: u32,
    core_alias_groups: []const FindingGroup,
    semantic_duplicate_groups: []const FindingGroup,
    core_candidate_findings: []const CandidateFinding,

    fn findingCount(self: AuditReport) usize {
        return self.core_alias_groups.len + self.semantic_duplicate_groups.len;
    }

    fn render(self: AuditReport) void {
        std.debug.print(
            "pub const audit: scanned {d} files, found {d} top-level non-core public const declarations\n",
            .{ self.scanned_file_count, self.pub_const_count },
        );

        if (self.findingCount() == 0) {
            std.debug.print("pub const audit: no findings\n", .{});
            return;
        }

        if (self.core_alias_groups.len != 0) {
            std.debug.print(
                "\nCore-owned aliases outside serval-core ({d} groups):\n",
                .{self.core_alias_groups.len},
            );
            for (self.core_alias_groups) |group| {
                renderGroup(group);
            }
        }

        if (self.semantic_duplicate_groups.len != 0) {
            std.debug.print(
                "\nSemantic duplicate public const declarations outside serval-core ({d} groups):\n",
                .{self.semantic_duplicate_groups.len},
            );
            for (self.semantic_duplicate_groups) |group| {
                renderGroup(group);
            }
        }

        if (self.core_candidate_findings.len != 0) {
            std.debug.print(
                "\nShared pub const candidates for serval-core ({d} advisory findings):\n",
                .{self.core_candidate_findings.len},
            );
            for (self.core_candidate_findings) |finding| {
                renderCandidateFinding(finding);
            }
        }
    }
};

const CandidateFinding = struct {
    record: PubConstRecord,
    reference_modules: []const []const u8,
    reference_files: []const []const u8,
};

pub fn main(process_init: std.process.Init) !void {
    var arena_state = std.heap.ArenaAllocator.init(process_init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cli = try parseCli(process_init.minimal.args, arena);
    const report = try auditRepository(arena, process_init.io, cli.repo_root);
    report.render();

    if (cli.mode == .strict and report.findingCount() != 0) {
        return error.AuditFailed;
    }
}

fn parseCli(args_source: std.process.Args, allocator: std.mem.Allocator) !CliConfig {
    var config = CliConfig{};
    var arg_iter = try std.process.Args.Iterator.initAllocator(args_source, allocator);
    defer arg_iter.deinit();

    _ = arg_iter.next() orelse return error.MissingArgv0;

    var seen_arg_count: u8 = 1;
    while (arg_iter.next()) |arg_z| {
        seen_arg_count += 1;
        if (seen_arg_count > max_arg_count) return error.TooManyArguments;
        const arg: []const u8 = arg_z;
        if (std.mem.eql(u8, arg, "--report-only")) {
            config.mode = .report_only;
            continue;
        }
        if (std.mem.eql(u8, arg, "--repo-root")) {
            const repo_root = arg_iter.next() orelse return error.MissingRepoRootPath;
            config.repo_root = repo_root;
            continue;
        }
        return error.UnknownArgument;
    }

    assert(config.repo_root.len != 0);
    return config;
}

fn auditRepository(
    allocator: std.mem.Allocator,
    io: std.Io,
    repo_root: []const u8,
) !AuditReport {
    assert(repo_root.len != 0);

    var repo_dir = try std.Io.Dir.openDirAbsolute(io, repo_root, .{ .iterate = true });
    defer repo_dir.close(io);

    var walker = try repo_dir.walk(allocator);
    defer walker.deinit();

    var records: std.ArrayList(PubConstRecord) = .empty;
    var source_files: std.ArrayList(SourceFile) = .empty;

    var scanned_file_count: u32 = 0;
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isServalZigPath(entry.path)) continue;

        const source = try repo_dir.readFileAlloc(
            io,
            entry.path,
            allocator,
            .limited(max_source_file_size_bytes),
        );

        try source_files.append(allocator, try analyzeSourceContext(allocator, entry.path, source));

        if (isAuditedZigPath(entry.path)) {
            scanned_file_count += 1;
            if (scanned_file_count > max_scanned_files) return error.TooManyAuditedFiles;

            const file_records = try analyzeSourceFile(allocator, entry.path, source);
            for (file_records) |record| {
                try records.append(allocator, record);
            }
        }
    }

    sortRecords(records.items);

    const core_alias_groups = try buildCoreAliasGroups(allocator, records.items);
    const semantic_duplicate_groups = try buildSemanticDuplicateGroups(allocator, records.items);
    const core_candidate_findings = try buildCoreCandidateFindings(
        allocator,
        records.items,
        source_files.items,
    );

    return .{
        .scanned_file_count = scanned_file_count,
        .pub_const_count = @intCast(records.items.len),
        .core_alias_groups = core_alias_groups,
        .semantic_duplicate_groups = semantic_duplicate_groups,
        .core_candidate_findings = core_candidate_findings,
    };
}

fn analyzeSourceFile(
    allocator: std.mem.Allocator,
    rel_path: []const u8,
    source: []const u8,
) ![]const PubConstRecord {
    const rel_path_copy = try allocator.dupe(u8, rel_path);
    const basename = baseName(rel_path_copy);
    const module = moduleName(rel_path_copy);

    const source_z = try allocator.dupeZ(u8, source);
    var tree = try std.zig.Ast.parse(allocator, source_z, .zig);
    defer tree.deinit(allocator);

    if (tree.errors.len != 0) return error.ParseErrorsPresent;

    var aliases: std.ArrayList(AliasDecl) = .empty;
    var pending_pub_consts: std.ArrayList(PendingPubConst) = .empty;

    const decls = tree.rootDecls();
    for (decls) |decl| {
        const full_decl = tree.fullVarDecl(decl) orelse continue;
        if (tree.tokenTag(full_decl.ast.mut_token) != .keyword_const) continue;

        const name_token = full_decl.ast.mut_token + 1;
        if (!isIdentifierToken(tree.tokenTag(name_token))) continue;

        const init_node = full_decl.ast.init_node.unwrap() orelse continue;
        const symbol = try allocator.dupe(u8, tree.tokenSlice(name_token));
        const raw_expr = try normalizedNodeTokens(allocator, tree, init_node);

        if (full_decl.visib_token == null) {
            try aliases.append(allocator, .{
                .name = symbol,
                .raw_expr = raw_expr,
            });
            continue;
        }

        const location = tree.tokenLocation(0, name_token);
        try pending_pub_consts.append(allocator, .{
            .symbol = symbol,
            .line = @intCast(location.line + 1),
            .raw_expr = raw_expr,
        });
    }

    var records: std.ArrayList(PubConstRecord) = .empty;
    for (pending_pub_consts.items) |pending| {
        const resolved_expr = try resolveExpr(allocator, pending.raw_expr, aliases.items, 0);
        try records.append(allocator, .{
            .module = module,
            .rel_path = rel_path_copy,
            .basename = basename,
            .symbol = pending.symbol,
            .line = pending.line,
            .raw_expr = pending.raw_expr,
            .resolved_expr = resolved_expr,
            .kind = classifyPubConst(basename, resolved_expr),
        });
    }

    return try records.toOwnedSlice(allocator);
}

fn analyzeSourceContext(
    allocator: std.mem.Allocator,
    rel_path: []const u8,
    source: []const u8,
) !SourceFile {
    const rel_path_copy = try allocator.dupe(u8, rel_path);
    const module = moduleName(rel_path_copy);

    const source_copy = try allocator.dupe(u8, source);
    const source_z = try allocator.dupeZ(u8, source);
    var tree = try std.zig.Ast.parse(allocator, source_z, .zig);
    defer tree.deinit(allocator);

    if (tree.errors.len != 0) return error.ParseErrorsPresent;

    var aliases: std.ArrayList(AliasDecl) = .empty;
    const decls = tree.rootDecls();
    for (decls) |decl| {
        const full_decl = tree.fullVarDecl(decl) orelse continue;
        if (tree.tokenTag(full_decl.ast.mut_token) != .keyword_const) continue;

        const name_token = full_decl.ast.mut_token + 1;
        if (!isIdentifierToken(tree.tokenTag(name_token))) continue;

        const init_node = full_decl.ast.init_node.unwrap() orelse continue;
        const symbol = try allocator.dupe(u8, tree.tokenSlice(name_token));
        const raw_expr = try normalizedNodeTokens(allocator, tree, init_node);
        try aliases.append(allocator, .{
            .name = symbol,
            .raw_expr = raw_expr,
        });
    }

    var module_imports: std.ArrayList(ModuleImport) = .empty;
    for (aliases.items) |alias| {
        const resolved = try resolveExpr(allocator, alias.raw_expr, aliases.items, 0);
        if (importedModuleName(resolved)) |target_module| {
            if (!std.mem.startsWith(u8, target_module, "serval-")) continue;
            try module_imports.append(allocator, .{
                .alias = alias.name,
                .target_module = target_module,
            });
        }
    }

    return .{
        .module = module,
        .rel_path = rel_path_copy,
        .source = source_copy,
        .module_imports = try module_imports.toOwnedSlice(allocator),
    };
}

fn classifyPubConst(basename: []const u8, resolved_expr: []const u8) PubConstKind {
    assert(resolved_expr.len != 0);

    if (std.mem.eql(u8, basename, "mod.zig") and isModReexportExpr(resolved_expr)) {
        return .mod_reexport;
    }
    if (isTypeDefinitionExpr(resolved_expr)) return .type_definition;
    if (isLiteralExpr(resolved_expr)) return .literal;
    if (isCoreAliasExpr(resolved_expr)) return .core_alias;
    return .symbolic_expr;
}

fn buildCoreAliasGroups(
    allocator: std.mem.Allocator,
    records: []const PubConstRecord,
) ![]const FindingGroup {
    var used = try allocator.alloc(bool, records.len);
    @memset(used, false);

    var groups: std.ArrayList(FindingGroup) = .empty;

    var i: usize = 0;
    while (i < records.len) : (i += 1) {
        if (used[i]) continue;
        if (records[i].kind != .core_alias) continue;

        used[i] = true;
        var members: std.ArrayList(PubConstRecord) = .empty;
        try members.append(allocator, records[i]);

        var j: usize = i + 1;
        while (j < records.len) : (j += 1) {
            if (used[j]) continue;
            if (records[j].kind != .core_alias) continue;
            if (!std.mem.eql(u8, records[i].resolved_expr, records[j].resolved_expr)) continue;
            used[j] = true;
            try members.append(allocator, records[j]);
        }

        const group_members = try members.toOwnedSlice(allocator);
        sortRecords(group_members);
        try groups.append(allocator, .{
            .key = records[i].resolved_expr,
            .members = group_members,
        });
    }

    sortGroups(groups.items);
    return try groups.toOwnedSlice(allocator);
}

fn buildSemanticDuplicateGroups(
    allocator: std.mem.Allocator,
    records: []const PubConstRecord,
) ![]const FindingGroup {
    var used = try allocator.alloc(bool, records.len);
    @memset(used, false);

    var groups: std.ArrayList(FindingGroup) = .empty;

    var i: usize = 0;
    while (i < records.len) : (i += 1) {
        if (used[i]) continue;
        if (!isDuplicateCandidate(records[i])) continue;

        var members: std.ArrayList(PubConstRecord) = .empty;
        try members.append(allocator, records[i]);

        var j: usize = i + 1;
        while (j < records.len) : (j += 1) {
            if (used[j]) continue;
            if (!isDuplicateCandidate(records[j])) continue;
            if (!std.mem.eql(u8, records[i].resolved_expr, records[j].resolved_expr)) continue;
            try members.append(allocator, records[j]);
        }

        if (members.items.len > 1) {
            used[i] = true;
            j = i + 1;
            while (j < records.len) : (j += 1) {
                if (!isDuplicateCandidate(records[j])) continue;
                if (!std.mem.eql(u8, records[i].resolved_expr, records[j].resolved_expr)) continue;
                used[j] = true;
            }

            const group_members = try members.toOwnedSlice(allocator);
            sortRecords(group_members);
            try groups.append(allocator, .{
                .key = records[i].resolved_expr,
                .members = group_members,
            });
        }
    }

    sortGroups(groups.items);
    return try groups.toOwnedSlice(allocator);
}

fn buildCoreCandidateFindings(
    allocator: std.mem.Allocator,
    records: []const PubConstRecord,
    source_files: []const SourceFile,
) ![]const CandidateFinding {
    var findings: std.ArrayList(CandidateFinding) = .empty;

    for (records) |record| {
        if (!isCorePromotionCandidate(record)) continue;

        var reference_modules: std.ArrayList([]const u8) = .empty;
        var reference_files: std.ArrayList([]const u8) = .empty;

        for (source_files) |source_file| {
            if (std.mem.eql(u8, source_file.module, record.module)) continue;
            if (!referencesModuleRootSymbol(source_file, record.module, record.symbol)) continue;

            try appendUniqueString(allocator, &reference_modules, source_file.module);
            try appendUniqueString(allocator, &reference_files, source_file.rel_path);
        }

        if (reference_modules.items.len < min_candidate_external_modules) continue;

        sortStrings(reference_modules.items);
        sortStrings(reference_files.items);
        try findings.append(allocator, .{
            .record = record,
            .reference_modules = try reference_modules.toOwnedSlice(allocator),
            .reference_files = try reference_files.toOwnedSlice(allocator),
        });
    }

    sortCandidateFindings(findings.items);
    return try findings.toOwnedSlice(allocator);
}

fn isDuplicateCandidate(record: PubConstRecord) bool {
    return switch (record.kind) {
        .symbolic_expr => true,
        .core_alias, .mod_reexport, .type_definition, .literal => false,
    };
}

fn isCorePromotionCandidate(record: PubConstRecord) bool {
    return switch (record.kind) {
        .symbolic_expr, .literal => true,
        .core_alias, .mod_reexport, .type_definition => false,
    };
}

fn renderGroup(group: FindingGroup) void {
    std.debug.print("  {s}\n", .{group.key});
    const report_len = @min(group.members.len, max_reported_members_per_group);
    for (group.members[0..report_len]) |member| {
        std.debug.print(
            "    - {s}:{d} -> {s}\n",
            .{ member.rel_path, member.line, member.symbol },
        );
    }
    if (group.members.len > report_len) {
        std.debug.print("    - ... {d} more\n", .{group.members.len - report_len});
    }
}

fn renderCandidateFinding(finding: CandidateFinding) void {
    std.debug.print(
        "  {s}:{d} -> {s} referenced by {d} external modules\n",
        .{
            finding.record.rel_path,
            finding.record.line,
            finding.record.symbol,
            finding.reference_modules.len,
        },
    );
    std.debug.print("    modules: ", .{});
    for (finding.reference_modules, 0..) |module, index| {
        if (index != 0) std.debug.print(", ", .{});
        std.debug.print("{s}", .{module});
    }
    std.debug.print("\n", .{});
}

fn isAuditedZigPath(path: []const u8) bool {
    if (!isServalZigPath(path)) return false;
    if (std.mem.startsWith(u8, path, "serval-core/")) return false;
    return true;
}

fn isServalZigPath(path: []const u8) bool {
    if (!std.mem.endsWith(u8, path, ".zig")) return false;
    if (!std.mem.startsWith(u8, path, "serval-")) return false;
    return true;
}

fn normalizedNodeTokens(
    allocator: std.mem.Allocator,
    tree: std.zig.Ast,
    node: std.zig.Ast.Node.Index,
) ![]const u8 {
    const first_token = tree.firstToken(node);
    const last_token = tree.lastToken(node);
    assert(first_token <= last_token);

    var buffer: std.ArrayList(u8) = .empty;

    var token_index = first_token;
    while (token_index <= last_token) : (token_index += 1) {
        const token_slice = tree.tokenSlice(token_index);
        try buffer.appendSlice(allocator, token_slice);
    }

    return try buffer.toOwnedSlice(allocator);
}

fn resolveExpr(
    allocator: std.mem.Allocator,
    expr: []const u8,
    aliases: []AliasDecl,
    depth: u8,
) ![]const u8 {
    assert(expr.len != 0);
    if (depth >= max_alias_resolution_depth) return error.AliasResolutionDepthExceeded;

    const head = leadingIdentifier(expr) orelse return expr;
    const alias = findAlias(aliases, head) orelse return expr;

    const alias_resolved = if (alias.resolved_expr) |resolved| resolved else blk: {
        const resolved = try resolveExpr(allocator, alias.raw_expr, aliases, depth + 1);
        alias.resolved_expr = resolved;
        break :blk resolved;
    };

    const suffix = expr[head.len..];
    if (suffix.len == 0) return alias_resolved;

    var buffer: std.ArrayList(u8) = .empty;
    try buffer.appendSlice(allocator, alias_resolved);
    try buffer.appendSlice(allocator, suffix);
    return try buffer.toOwnedSlice(allocator);
}

fn leadingIdentifier(expr: []const u8) ?[]const u8 {
    if (expr.len == 0) return null;

    if (expr.len >= 3 and expr[0] == '@' and expr[1] == '"') {
        var i: usize = 2;
        while (i < expr.len) : (i += 1) {
            if (expr[i] == '"') return expr[0 .. i + 1];
        }
        return null;
    }

    if (!isIdentifierStart(expr[0])) return null;
    var end: usize = 1;
    while (end < expr.len and isIdentifierContinue(expr[end])) : (end += 1) {}
    return expr[0..end];
}

fn findAlias(aliases: []AliasDecl, name: []const u8) ?*AliasDecl {
    for (aliases) |*alias| {
        if (std.mem.eql(u8, alias.name, name)) return alias;
    }
    return null;
}

fn isModReexportExpr(expr: []const u8) bool {
    if (std.mem.startsWith(u8, expr, "@import(\"")) return true;
    return isSimplePathExpr(expr);
}

fn isTypeDefinitionExpr(expr: []const u8) bool {
    return std.mem.startsWith(u8, expr, "struct{") or
        std.mem.startsWith(u8, expr, "struct(") or
        std.mem.startsWith(u8, expr, "enum{") or
        std.mem.startsWith(u8, expr, "enum(") or
        std.mem.startsWith(u8, expr, "union{") or
        std.mem.startsWith(u8, expr, "union(") or
        std.mem.startsWith(u8, expr, "opaque{") or
        std.mem.startsWith(u8, expr, "error{");
}

fn isLiteralExpr(expr: []const u8) bool {
    if (expr.len == 0) return false;
    if (expr[0] == '"' or expr[0] == '\'') return true;
    if (std.ascii.isDigit(expr[0])) return true;
    if (expr[0] == '-' and expr.len > 1 and std.ascii.isDigit(expr[1])) return true;
    return std.mem.eql(u8, expr, "true") or
        std.mem.eql(u8, expr, "false") or
        std.mem.eql(u8, expr, "null");
}

fn isCoreAliasExpr(expr: []const u8) bool {
    return std.mem.eql(u8, expr, "@import(\"serval-core\")") or
        std.mem.startsWith(u8, expr, "@import(\"serval-core\").");
}

fn importedModuleName(expr: []const u8) ?[]const u8 {
    const prefix = "@import(\"";
    if (!std.mem.startsWith(u8, expr, prefix)) return null;
    if (expr.len <= prefix.len + 2) return null;

    var index = prefix.len;
    while (index < expr.len) : (index += 1) {
        if (expr[index] == '"') {
            if (index + 1 >= expr.len or expr[index + 1] != ')') return null;
            if (index + 2 != expr.len) return null;
            return expr[prefix.len..index];
        }
    }
    return null;
}

fn isSimplePathExpr(expr: []const u8) bool {
    if (expr.len == 0) return false;

    var i: usize = 0;
    while (i < expr.len) {
        const ident = leadingIdentifier(expr[i..]) orelse return false;
        i += ident.len;
        if (i == expr.len) return true;
        if (expr[i] != '.') return false;
        i += 1;
    }
    return true;
}

fn referencesModuleRootSymbol(
    source_file: SourceFile,
    target_module: []const u8,
    symbol: []const u8,
) bool {
    if (containsModuleSymbolPattern(source_file.source, target_module, symbol)) return true;

    for (source_file.module_imports) |module_import| {
        if (!std.mem.eql(u8, module_import.target_module, target_module)) continue;
        if (containsAliasSymbolPattern(source_file.source, module_import.alias, symbol)) return true;
    }

    return false;
}

fn containsModuleSymbolPattern(source: []const u8, target_module: []const u8, symbol: []const u8) bool {
    var pattern: [256]u8 = undefined;
    const prefix = std.fmt.bufPrint(&pattern, "@import(\"{s}\").{s}", .{ target_module, symbol }) catch
        return false;
    return containsPathReference(source, prefix, symbol);
}

fn containsAliasSymbolPattern(source: []const u8, alias: []const u8, symbol: []const u8) bool {
    var pattern: [256]u8 = undefined;
    const prefix = std.fmt.bufPrint(&pattern, "{s}.{s}", .{ alias, symbol }) catch
        return false;
    return containsPathReference(source, prefix, symbol);
}

fn containsPathReference(source: []const u8, pattern: []const u8, symbol: []const u8) bool {
    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, source, start_index, pattern)) |match_index| {
        const end_index = match_index + pattern.len;
        if (isReferenceBoundaryBefore(source, match_index) and
            isReferenceBoundaryAfter(source, end_index, symbol))
        {
            return true;
        }
        start_index = match_index + 1;
    }
    return false;
}

fn isReferenceBoundaryBefore(source: []const u8, index: usize) bool {
    if (index == 0) return true;
    const prev = source[index - 1];
    return !isIdentifierContinue(prev) and prev != '.';
}

fn isReferenceBoundaryAfter(source: []const u8, end_index: usize, symbol: []const u8) bool {
    _ = symbol;
    if (end_index >= source.len) return true;
    const next = source[end_index];
    return !isIdentifierContinue(next);
}

fn isIdentifierToken(tag: std.zig.Token.Tag) bool {
    return switch (tag) {
        .identifier => true,
        else => false,
    };
}

fn isIdentifierStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte) or byte == '_';
}

fn isIdentifierContinue(byte: u8) bool {
    return isIdentifierStart(byte) or std.ascii.isDigit(byte);
}

fn baseName(path: []const u8) []const u8 {
    const maybe_index = std.mem.lastIndexOfScalar(u8, path, '/');
    if (maybe_index) |index| return path[index + 1 ..];
    return path;
}

fn moduleName(path: []const u8) []const u8 {
    const slash_index = std.mem.indexOfScalar(u8, path, '/') orelse path.len;
    return path[0..slash_index];
}

fn sortRecords(records: []PubConstRecord) void {
    if (records.len < 2) return;

    var i: usize = 0;
    while (i < records.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < records.len) : (j += 1) {
            if (recordLessThan(records[j], records[i])) {
                const tmp = records[i];
                records[i] = records[j];
                records[j] = tmp;
            }
        }
    }
}

fn recordLessThan(a: PubConstRecord, b: PubConstRecord) bool {
    const path_order = std.mem.order(u8, a.rel_path, b.rel_path);
    if (path_order != .eq) return path_order == .lt;
    if (a.line != b.line) return a.line < b.line;
    return std.mem.order(u8, a.symbol, b.symbol) == .lt;
}

fn sortGroups(groups: []FindingGroup) void {
    if (groups.len < 2) return;

    var i: usize = 0;
    while (i < groups.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < groups.len) : (j += 1) {
            if (groupLessThan(groups[j], groups[i])) {
                const tmp = groups[i];
                groups[i] = groups[j];
                groups[j] = tmp;
            }
        }
    }
}

fn groupLessThan(a: FindingGroup, b: FindingGroup) bool {
    const key_order = std.mem.order(u8, a.key, b.key);
    if (key_order != .eq) return key_order == .lt;
    return a.members.len < b.members.len;
}

fn sortCandidateFindings(findings: []CandidateFinding) void {
    if (findings.len < 2) return;

    var i: usize = 0;
    while (i < findings.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < findings.len) : (j += 1) {
            if (candidateFindingLessThan(findings[j], findings[i])) {
                const tmp = findings[i];
                findings[i] = findings[j];
                findings[j] = tmp;
            }
        }
    }
}

fn candidateFindingLessThan(a: CandidateFinding, b: CandidateFinding) bool {
    if (a.reference_modules.len != b.reference_modules.len) {
        return a.reference_modules.len > b.reference_modules.len;
    }
    return recordLessThan(a.record, b.record);
}

fn appendUniqueString(
    allocator: std.mem.Allocator,
    strings: *std.ArrayList([]const u8),
    value: []const u8,
) !void {
    for (strings.items) |item| {
        if (std.mem.eql(u8, item, value)) return;
    }
    try strings.append(allocator, value);
}

fn sortStrings(strings: [][]const u8) void {
    if (strings.len < 2) return;

    var i: usize = 0;
    while (i < strings.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < strings.len) : (j += 1) {
            if (std.mem.order(u8, strings[j], strings[i]) == .lt) {
                const tmp = strings[i];
                strings[i] = strings[j];
                strings[j] = tmp;
            }
        }
    }
}

test "analyzeSourceFile resolves serval-core aliases and classifies them" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source =
        \\const config = @import("serval-core").config;
        \\pub const MAX_ROUTES = config.MAX_ROUTES;
    ;

    const records = try analyzeSourceFile(arena, "serval-router/router.zig", source);
    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual(PubConstKind.core_alias, records[0].kind);
    try std.testing.expectEqualStrings("@import(\"serval-core\").config.MAX_ROUTES", records[0].resolved_expr);
}

test "analyzeSourceFile classifies mod.zig reexports separately" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source =
        \\const handler = @import("handler.zig");
        \\pub const Handler = handler.Handler;
    ;

    const records = try analyzeSourceFile(arena, "serval-waf/mod.zig", source);
    try std.testing.expectEqual(@as(usize, 1), records.len);
    try std.testing.expectEqual(PubConstKind.mod_reexport, records[0].kind);
}

test "semantic duplicate grouping ignores literals and groups symbolic expressions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const records = [_]PubConstRecord{
        .{
            .module = "serval-a",
            .rel_path = "serval-a/a.zig",
            .basename = "a.zig",
            .symbol = "MAX_ROUTES",
            .line = 1,
            .raw_expr = "@import(\"serval-core\").config.MAX_ROUTES*2",
            .resolved_expr = "@import(\"serval-core\").config.MAX_ROUTES*2",
            .kind = .symbolic_expr,
        },
        .{
            .module = "serval-b",
            .rel_path = "serval-b/b.zig",
            .basename = "b.zig",
            .symbol = "MAX_EFFECTIVE_ROUTES",
            .line = 2,
            .raw_expr = "@import(\"serval-core\").config.MAX_ROUTES*2",
            .resolved_expr = "@import(\"serval-core\").config.MAX_ROUTES*2",
            .kind = .symbolic_expr,
        },
        .{
            .module = "serval-c",
            .rel_path = "serval-c/c.zig",
            .basename = "c.zig",
            .symbol = "signal_name",
            .line = 3,
            .raw_expr = "\"behavior-request-burst\"",
            .resolved_expr = "\"behavior-request-burst\"",
            .kind = .literal,
        },
        .{
            .module = "serval-d",
            .rel_path = "serval-d/d.zig",
            .basename = "d.zig",
            .symbol = "signal_name_2",
            .line = 4,
            .raw_expr = "\"behavior-request-burst\"",
            .resolved_expr = "\"behavior-request-burst\"",
            .kind = .literal,
        },
    };

    const groups = try buildSemanticDuplicateGroups(arena, &records);
    try std.testing.expectEqual(@as(usize, 1), groups.len);
    try std.testing.expectEqualStrings("@import(\"serval-core\").config.MAX_ROUTES*2", groups[0].key);
    try std.testing.expectEqual(@as(usize, 2), groups[0].members.len);
}

test "core candidate findings report shared exported values used by other modules" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const records = [_]PubConstRecord{
        .{
            .module = "serval-router",
            .rel_path = "serval-router/router.zig",
            .basename = "router.zig",
            .symbol = "MAX_ROUTES",
            .line = 10,
            .raw_expr = "64",
            .resolved_expr = "64",
            .kind = .literal,
        },
    };

    const source_files = [_]SourceFile{
        .{
            .module = "serval-router",
            .rel_path = "serval-router/mod.zig",
            .source = "pub const MAX_ROUTES = router.MAX_ROUTES;",
            .module_imports = &.{},
        },
        .{
            .module = "serval-server",
            .rel_path = "serval-server/runtime.zig",
            .source = "const router = @import(\"serval-router\"); const x = router.MAX_ROUTES;",
            .module_imports = &.{
                .{ .alias = "router", .target_module = "serval-router" },
            },
        },
        .{
            .module = "serval-k8s-gateway",
            .rel_path = "serval-k8s-gateway/translator.zig",
            .source = "const router = @import(\"serval-router\"); const y = router.MAX_ROUTES;",
            .module_imports = &.{
                .{ .alias = "router", .target_module = "serval-router" },
            },
        },
    };

    const findings = try buildCoreCandidateFindings(arena, &records, &source_files);
    try std.testing.expectEqual(@as(usize, 1), findings.len);
    try std.testing.expectEqualStrings("MAX_ROUTES", findings[0].record.symbol);
    try std.testing.expectEqual(@as(usize, 2), findings[0].reference_modules.len);
}
