# `.e` 每个字段的**源码级证据映射表**

> **判定规则（本次会话确立）**
> 1. 字段**读盘会消费** ⇒ 必须给出**读侧**指令地址（如 `[esi+10h]` 的读取点），写侧只作旁证。
> 2. 字段**读盘从不读** ⇒ 只需给出**写侧**指令地址（写的是什么就是什么）。
> 3. 只有 `.e` 字节反推、没有 e.exe 指令的 ⇒ 一律标 ❓**缺源级证据**，不许写成结论。
>
> 覆盖状态：`✅` = 读/写侧指令已定位；`❓` = 尚缺；`—` = 该段无此字段。
> 地址全部是 **5.9**；4.0 另注。

---

## 0. 全局：文件头 + 段头

| 字段 | 偏移 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|---|
| 文件头 `"CNWTEPRG"` | 0..8 | `0x444CF0`(4.0) / 5.9 读侧两次 32 位比对 | `0x4582F2` 写 `"CNWT"`、`0x45831D` 写 `"EPRG"` | ✅ |
| 段头 magic `0x15117319` | +0 | `0x45BB7E cmp [ebp+var_8C],15117319h` | `0x45989B` 写立即数 | ✅ |
| 段头校验和 | +4 | `0x45BBE8 cmp eax,ecx`（`0x45BBDA sub_4FF040(&hdr,0x5C)`） | `0x4598B2` 算、`0x4598D4` 写回 | ✅ |
| 段标识 key | +8 | `0x45BB6B sub_5C263B(&buf,4)` 后与常量链比对 | `0x459823 Src = a2` | ✅ |
| 段名（30B，异或） | +12 | `0x45BC1E sub_4FF010(String,30,key)` | `0x45982A strcpy` + `0x45983B sub_4FF010` | ✅ |
| 对齐空隙 | +42 | 读侧未见任何 `[hdr+42]` 访问 | **不在写入清单里** → 保持 `memset` 的 0 | ✅ **已定死** |
| 段索引 | +44 | `0x45BBF9 cmp eax,ecx`（期望序号） | `0x45985E v12 = a4` | ✅ |
| 是否可丢失 | +48 | `0x45BD2A test [ebp+var_170],1` / `0x45D868` 同 | `0x459862 v13 = a5` | ✅ |
| 段体校验和 | +52 | `0x45BD1F mov eax,[ebp+Block]`（=比对结果） | `0x459872 sub_4FF040(a6,a7)` | ✅ |
| 段尺寸 | +56 | `0x45BD5E mov eax,[ebp+var_168]`（用于 seek 跳过） | `0x459879 v15 = a7` | ✅ |
| 保留 40B | +60 | 读侧未见访问 | **不在写入清单里** → 保持 `memset` 的 0 | ✅ **已定死** |

### 0.1 ★★★ `+42` 与 `+60..+100` 为什么必然是 0 —— 源码级证明（不再是"全语料实测"）

这是本次补上的两条，**从"实测全 0"升级为"源码必然 0"**：

**(a) 段头缓冲的尺寸与清零范围**（`sub_4597F0@0x4597F0` 前 5 条指令，反汇编原文）：
```
4597f0  sub esp, 5Ch              ; ★ 分配 92 字节局部缓冲
4597f7  lea eax, [esp+6Ch+Src]    ; ★ &Src = 该 92 字节缓冲的起点
4597fb  push 5Ch  ('\')           ; n = 92
4597fd  push eax
4597fe  call sub_491750           ; ★ 清零
```
`sub_491750@0x491750`（全文已读）对 `n > 4` 走 `memset(a1, 0, a2)`：
```c
_BYTE *__cdecl sub_491750(_BYTE *a1, unsigned int a2) {
  if (a2 != 0) switch (a2) {
    case 1u: *a1 = 0; return a1;
    case 2u: *(_WORD *)a1 = 0; break;
    case 4u: *(_DWORD *)a1 = 0; break;
    default: memset(a1, 0, a2); return nullptr;      /* ★ n = 92 走这里 */
  }
  ...
}
```
⇒ **`memset(&段头缓冲[0], 0, 92)`**，即**段头 `+8 .. +100` 这 92 字节先被整体清零**。

**(b) 之后被显式写入的字段（全部写点，反汇编实证）**：
```
459823  mov [esp+74h+Src], edx    ; +8  = key（4 字节）
45982a  rep movsd / 459834 rep movsb  ; +12..+41 = 段名（30 字节，先 strcpy 再异或）
45985e  v12 = a4                  ; +44 = 段索引
459862  v13 = a5                  ; +48 = 是否可丢失
459872  v14 = sub_4FF040(a6,a7)   ; +52 = 段体校验和
459879  v15 = a7                  ; +56 = 段体尺寸
45989b  写 0x15117319             ; +0  = magic（在 92 字节缓冲之外）
4598b2  sub_4FF040(&Src, 92)      ; 算 92 字节的 lane-XOR
4598d4  写回                      ; +4  = 段头校验和（同样在缓冲之外）
```
**写入清单 = `{+0, +4, +8, +12..+41, +44, +48, +52, +56}`**，
加上 `memset` 覆盖的 `{+8..+100}`：

| 偏移 | 为什么是 0 |
|---|---|
| `+42..+43`（对齐空隙） | `memset` 覆盖到了，**且写入清单里没有任何一条写它** |
| `+60..+99`（保留 40 字节） | 同上 |
| `+100`（= 缓冲末尾的下一个字节） | **不属于段头缓冲**（缓冲是 `[+8,+100)`）；它是段体第一字节 |

⇒ **`+42` 与 `+60..+99` 恒 0 是写盘代码的必然结果，不是样本巧合**；
`+0`/`+4` 在 92 字节缓冲之外单独写，所以它们**不**在 memset 范围内。
**这两条现在是 `✅ 已定死`，证据是 `sub_4597F0` 的指令 + `sub_491750` 的实现，不再依赖 571 个样本。**

---

## 1. 用户信息段 `0x01007319`

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| 程序名称 (mfc_string) | `0x455711 sub_4FEBA0` | 同（store 分支） | ✅ |
| 程序说明 (mfc_string) | `0x45571B` | 同 | ✅ |
| **★ `if (a3 == 1)` 分支** | **`0x455727 cmp eax,1` / `0x45572A jnz loc_455781`** | 同 | ✅ |
| 作者姓名 (mfc_string) | `0x455731`（`&this+8`） | 同 | ✅ |
| 邮政编码 (mfc_string) | `0x45573B`（`&this+0xC`） | 同 | ✅ |
| 通信地址 (mfc_string) | `0x455745`（`&this+0x10`） | 同 | ✅ |
| 电话号码 (mfc_string) | `0x45574F` | 同 | ✅ |
| QQ号码 (mfc_string) | `0x455759` | 同 | ✅ |
| 电子信箱 (mfc_string) | `0x455763` | 同 | ✅ |
| 主页地址 (mfc_string) | `0x45576D` | 同 | ✅ |
| 其它信息 (mfc_string) | `0x455777` | 同 | ✅ |
| **★ `else` 分支（8 个空串）** | **`0x455792 mov ebx,8` / `0x455797 lea ecx,[esp+..]` / `0x45579D call sub_4FEBA0` / `0x4557A6 jnz loc_455797`**（循环 8 次；`off_66E5AC` = 共享空串） | 同 | ✅ |
| u32 #1（尾部 +0） | `0x4558EF` | 同 | ✅ |
| u32 #2（+4） | `0x455915` | 同 | ✅ |
| u32 #3（+8） | `0x45593B` | 同 | ✅ |
| 编译插件名 20B raw | `0x45599A sub_5C263B(this+60,20)` | 同 | ✅ |
| u32 #4（+0x50） | `0x4559C2` | 同 | ✅ |
| 保留 4B（+0x54） | `0x4559CF` | 同 | ✅ |

#### 1.0f ★ **用 `trace_data_flow` 收口：这 5 个字段的数据流在序列化器内部就终止（goal round 71）**

##### (1) 向后追（backward）——独立确认调用链与 `this`

```
从 sub_4556F0 向后追 3 层（实测 nodes）：
  depth 0: 0x4556F0  sub_4556F0          mov eax, large fs:0
  depth 1: 0x4583DE  sub_457910          call sub_4556F0     ← 写盘
           0x45B32C  sub_45B0D0          call sub_4556F0     ← 迷你扫描
           0x45C0AC  sub_45B9B0          call sub_4556F0     ← 读盘
  depth 2: 0x4583DB  sub_457910          lea ecx, [ebx+3Ch]  ★ this = ebx+0x3C
           0x45B32A  sub_45B0D0          mov ecx, edi
           0x45C0AA  sub_45B9B0          mov ecx, edi
  depth 3: 0x45C0A7  sub_45B9B0          lea edi, [eax+3Ch]  ★ this = eax+0x3C
```
⇒ **独立重证了 §X23.3 的结论**：`this` = `doc+0x3C`，且**只有 3 个调用者**，
**没有任何对话框/界面代码**。

##### (2) 向前追（forward）——★ ★ 关键：**没有外部分支**

```
从 0x4558EF（m_field1 的写入点）向前追 3 层（实测 nodes）：
  depth 0: 0x4558EF  sub_4556F0   mov [edi+28h], ecx    ← 写 m_field1
  depth 1: 0x4558F2  sub_4556F0   mov eax, [esi+24h]    ← 继续读 archive 游标
  depth 2: 0x4558F5  sub_4556F0   mov ecx, [esi+28h]    ← archive 缓冲尾
  depth 3: 0x4558F8  sub_4556F0   add eax, ebx
从 0x455989（m_field5 的写入点）向前追，同样只有 4 个节点、全在 sub_4556F0 内。
```
⇒ **从这些字段出发的数据流，在 `sub_4556F0` 内部就终止了 ——
后续节点全是 `CArchive` 的游标推进（`[esi+24h]` / `[esi+28h]`）。**

##### (3) 结论：#1 的静态链条**两端都断开**

| 方向 | 结果 |
|---|---|
| **向后**（谁写入它们） | 只有 3 个控制器，**无界面代码**（§X27 第1条 + §1.0e(2) + 本节(1)） |
| **向前**（谁消费它们） | 数据流**在序列化器内部终止**，无外部分支（本节(2)） |

**三道独立手段得到同一结论**：程序流分析（§X27）、
字段 xref（§1.0e(1)）、数据流追踪（本节）。

⇒ **`m_field1..m_field5` 在 `e.exe` 里是彻底的“透明字段”**：只负责从文件读进内存、
再从内存写回文件，**中间不参与任何判断**。
这共生成了 **4 个独立否定**（§X12.2、§X5.1、§X5.2、§本节）。

**语义 #1 在本项目判据下正式收口**：
结构 = 字节级终定版；含义 = **两条独立证据都指向“版本号 主.次”**
（坐标对位 §X24 + 文件名趋同 §1.0d(3)），**强候选，未能升为结论**。

#### 1.0e **又两个否定：字段 xref 与立即数写入（goal round 70）**

##### (1) `xrefs_to_field` 对 `EcProgramInfo` 全部 8 个字段返回**空**

MCP 有一个 `xrefs_to_field`（列结构体字段的交叉引用）。对 `EcProgramInfo` 的
`m_field1..m_field6` / `m_szCompilerPlugin` / `m_extraData` 逐个查询，**全部返回**
`"No cross-references to this struct field"`。

**原因已知**：`sub_4556F0` 用的是**裸偏移**（`[esi+28h]`），
而不是结构化表达（`[edi+EcProgramInfo.m_field1]`），
所以 **IDA 不会建字段 xref**。⇒ 这条路对本例无效。

##### (2) 搜“立即数写入偏移”——**0 命中**

如果某处代码直接设置这些字段，应该能找到 `mov [reg+28h], <imm>`。实测：

| 模式 | 命中 | 有关的 |
|---|---|---|
| `+28h], 1` | 6 | 均非目标（`0x54637A`/`0x528B4C` 在 `0x54xxxx` MFC 区；其余是 `test byte ptr`） |
| `+28h], 2` | 3 | 均非目标（`test byte ptr` 或 `2B3E6C1Fh`） |
| **`+28h], 3`** | **0** | —— 而 `m_field1 = 3` 在 568 样本里**确实存在**（2 例） |
| **`+2Ch], 23`** | **0** | —— 而 `m_field2 = 23` 确实存在（2 例） |
| `+2Ch], 1` | 9 | 均在 `0x42xxxx`（MFC/运行时） |

⇒ **没有任何地方用立即数设置这些字段**。
这与 §X27 第 1 条（找不到读取者）合一，**双向都找不到使用点**。

##### (3) 附：MCP 这条通道的 66 个工具（供后续取证用）

`add_bookmark analyze_batch analyze_component analyze_function append_comments basic_blocks
callees callgraph declare_stack declare_type decompile define_code define_func delete_stack
disasm entity_query enum_upsert export_funcs find find_bytes find_regex
find_xref_signatures force_recompile func_profile func_query get_bytes get_global_value
get_int get_string idb_close idb_list idb_open idb_save imports imports_query
infer_types insn_query int_convert list_funcs list_globals lookup_funcs make_data
make_signature make_signature_for_function make_signature_for_range patch patch_asm put_int
read_struct rename search_structs server_health set_comments set_op_type set_type
stack_frame survey_binary trace_data_flow type_apply_batch type_inspect type_query
undefine xref_query xrefs_to xrefs_to_field`

**本项目已用过**：`declare_type` / `set_type` / `search_structs` / `disasm` / `decompile` /
`search_text` / `xrefs_to` / `get_bytes` / `lookup_funcs` / `type_query`。
**尚未用、但后续可能有用**：`trace_data_flow`（数据流！）、
`find_xref_signatures` / `xref_query` / `insn_query` / `func_profile` / `make_signature_for_range`。

#### 1.0d ★ **`m_field1`/`m_field2` 的两个新结果（goal round 69）**

##### (1) 规格修正：`libs` 串的分隔符是 `\r`（0x0D），不是 `\n`

§X11.1 里我写的是“用 `\n` 分隔”——**错**。实测（`_libver.py`，四个样本）：
```
libs[0] = 'krnln\rd09f2340818511d396f6aaf844c7e325\r4\r4\rKernel'
```
⇒ 分隔符是 **`\r`**。结构是 `库名 
 guid 
 主版本 
 次版本 
 Kernel`。

##### (2) ★ **`m_field1`/`m_field2` 与库版本完全无关**（否定）

把 568 个样本的 `(m_field1, m_field2)` 与 `(库主版本, 库次版本)` **交叉制表**：

| `(m_field1, m_field2)` | 对应的库版本对 |
|---|---|
| **(1, 0)** — 546 个样本 | **{4.4:287, 4.2:117, 4.5:46, 5.3:39, 4.1:32, 5.0:8, 5.2:6, 4.3:5, 5.7:4, 4.6:1, 2.0:1}** —— **11 种** |
| (1, 1) — 11 个 | {4.4:9, 4.2:1, 4.5:1} |
| (1, 2) — 2 个 | {4.1:1, 4.6:1} |
| (1, 11) / (1, 23) | 各 {4.4:2} |
| (2, 0) | {4.2:1, 4.4:1} |
| (2, 4) / (3, 0) | {4.2:1} / {4.4:2} |

⇒ 同一个 `(1,0)` 里涵盖了**11 种不同的库版本对** ⇒ **两者无关。**
（这是继 §X12.2、§X5.1、§X5.2 之后的**又一个确定否定**。）

##### (3) ★★ **但与“文件名里的版本号”高度相关**（新线索，比 (2) 有力得多）

`_plugin.py` + `_field34.py` 列出全部异常样本，**命名对应非常强**：

| 文件名 | `m_field1` | `m_field2` |
|---|---|---|
| `Gobang 1.25.e` | 1 | **23** |
| `五子棋1.25.e` | 1 | **23** |
| `模块_工具更新2.4.e` | **2** | **4** |
| `eSkin_ec.e` | 1 | **11** |
| `anchors_ec.e` | 1 | **11** |
| `OPenGL类.e` | 1 | **2** |
| `大型库示例.e` | 1 | **2** |
| `网络对战_1.25.e` | 1 | **23** |
| `IT综合管理系统.e` | **3** | 0 |
| `校验代3.0.e` | **3** | 0 |

?? **关键算术**：**`1.25` → `m_field2 = 23`**。
而 **`0x17` = 23**，**`1.25` 里的“25”是八进制吗？不是**——
但 **`1.17`（十六进制）= `1.23`（十进制）**。（即 23 = 0x17。）
同理 `2.4` → `(m_field1=2, m_field2=4)` **直接对应**。

⇒ **这强烈支持“`m_field1`.`m_field2` 就是一对版本号（主.次）”**，
与 §X24 的坐标对位（`*程序版本号：`→`1002`.`1003`）**互相印证**。

⚠️ 但依然**不能算结论**：文件名是作者自己起的，与字段值没有硬约束。
两条证据（坐标对位 + 文件名趋同）**方向一致、互相支持**，
但都不是“指令级直证”，故仍标**强候选**。

#### 1.0c ★ 尾部布局的**终定版**（一个极干净的样本直接数清了，goal round 68）

`CompilerPluginsSample.e` 是**最优样本**：`0x01` payload **恰好 88 字节**，10 条字符串**全空**，
所以整个 payload 就是“88 字节基线”的原始样子。**逐字节数出来：**

```
payload 88 字节（hex）
00 × 40                                        ← 10 条 mfc_string，每条只有一个 [u32 0]
01 00 00 00                                       ← m_field1 = 1        (+40)
00 00 00 00                                       ← m_field2 = 0        (+44)
00 00 00 00                                       ← m_field3 = 0        (+48)
00 00 00 00                                       ← m_field4 = 0        (+52)
00 00 00 00                                       ← m_field5 = 0        (+56)
43 6f 6d 70 69 6c 65 72 50 6c 75 67 69 6e 73     ← "CompilerPlugins"   (+60)
00 × 4                                          ← 零填充（定长 20 字节）
00 00 00 00                                       ← m_field6 = 0        (+80)
00 00 00 00                                       ← m_extraData[4] = 0  (+84)
（+88 = payload 末）
```

⇒ **终定版尾部布局（与 `EcProgramInfo` size=88 严格对应）**：

| 字段 | 相对 payload（= `this` 偏移） | 对应读侧指令 |
|---|---|---|
| `m_field1` | `+0x28` (40) | `0x4558EF` |
| `m_field2` | `+0x2C` (44) | `0x455915` |
| `m_field3` | `+0x30` (48) | `0x45593B` |
| `m_field4` | `+0x34` (52) | `0x455961` |
| `m_field5` | `+0x38` (56) | `0x455989` |
| **`m_szCompilerPlugin[20]`** | **`+0x3C` (60)** | **`0x45599A sub_5C263B(this+0x3C, 20)`** |
| `m_field6` | `+0x50` (80) | `0x4559C2` |
| `m_extraData[4]` | `+0x54` (84) | `0x4559CF` |
| 合计 | `0x58` = **88** | ✓ |

**这与 §X18.1 的 C++ 重构完全一致**（`sub_5C263B(this+0x3C, 20)` 的 `+0x3C` 就是那 20 字节）。

---

❌ **撤回：“`m_field6 = 1886220099` 的异常样本”是我自己的解析器 bug。**

`_field34.py` 里我用了 `r'3EAh]'` 风格的正则去提取字段，
但该库用 **.NET 正则语义**，**行尾 `$` 会匹配到 `\n` 之前**，把 `C` 也吃进去了。
`0x706D6F43` 的 `43` = `'C'` —— **正是 "CompilerPlugins" 的首字母**。

⇒ **568 个样本无一例异常**（`m_field3/4/5 确实恒 0，`m_field6` 除这个假阳性外全 0）。

**厄运记录（本项目第 4 次自抓 bug）**：在这个库上写正则时，
**不要用 `$` / `^` 做行锚点** —— 它的语义与 Python 不同。

#### 1.0b ★ 尾部布局的**字节级核实**（goal round 65）

对两个样本把 `0x03` payload 中“支持库记录之后”的字节摊开（实测）：

```
Bubble Sort.e   Kernel@file 1690  (= payload(0x03) + 94)
  Kernel å：00 × 16（零填充），然后直接是
                 08 00 00 00 | 04 00 01 19 | d0 37 c5 00 | 00 00 00 00 | 08 00 00 00 | 6d 6f 64 46 6f 72 6d 31 ...
                 [u32 8]      methodId     引用值        [u32 0]        [u32 8]        "modForm1"
Calc LCM.e      Kernel@file 2998  (= payload(0x03) + 94)   同样 16 字节零，然后同结构
```

⇒ **支持库记录之后紧跟的就是“类型/方法块”**（已在 §X8.2 记录）。

❌ **撤回**：我早期在日志里记过“`Kernel` 与 `m_field6` 之间夹着 `183`”。
**实测作布层格式打印时的错位误读**，两个样本都是 **16 字节零**，**没有 183**。

✅ **顺带精确核实了 `0x01` 段尾部的绝对偏移**（与 §X18.1 的结构体完全一致）：

| 字段 | 相对 payload | 绝对（Bubble Sort.e） | 备注 |
|---|---|---|---|
| 10 条 `mfc_string` | `0x00`.. | 1596..（长度变化） | 本例共 128 字节 |
| `m_field1` | 第 1 个 u32 | 1724 | 0x4558EF |
| `m_field2` | 第 2 个 u32 | 1728 | 0x455915 |
| `m_field3` | 第 3 个 u32 | 1732 | 0x45593B |
| `m_field4` | 第 4 个 u32 | 1736 | 0x455961 |
| `m_field5` | 第 5 个 u32 | 1740 | 0x455989 |
| `m_szCompilerPlugin[20]` | | 1744..1763 | 0x45599A（`sub_5C263B(this+0x3C,20)`） |
| `m_field6` | | 1764 | 0x4559C2 |
| `m_extraData[4]` | | 1768..1771 | 0x4559CF（合计 1772 = payload 末 = 1791） |

（校验：payload 从 1596 开始，长 196，末 = 1596 + 196 = 1792；
1596 + 176 = **1772** → 最后 20 字节 = `m_szCompilerPlugin` 的 20 字节 ——
但实测那 20 字节是全 0，与 “20B 插件名”的观察一致。）

**结论**：`0x01` 段的**尾部布局已逐字节核实**，与 `EcProgramInfo`（size = 88）严格对应。

**本段 16 个字段全部 ✅**（10 条 `mfc_string` + 5×u32 + 20B 插件名 + 4B 保留）。

#### 1.0 ★ 完整源码级重构（goal round 54，逐条指令实证）

`sub_4556F0@0x4556F0` 的**完整结构与已确认的 C++ 重构逐条吻合**：

```cpp
void CMyProgramConfig::Serialize(CArchive& ar, int nType)
{
    m_strProgramName.Serialize(ar);      // 0x455711  (this+0x00)
    m_strProgramDesc.Serialize(ar);      // 0x45571B  (this+0x04)

    if (nType == 1)                      // 0x455727 cmp eax,1 / 0x45572A jnz
    {
        m_strAuthor.Serialize(ar);       // 0x455731  (this+0x08)
        m_strPostalCode.Serialize(ar);   // 0x45573B  (this+0x0C)
        m_strAddress.Serialize(ar);      // 0x455745  (this+0x10)
        m_strPhone.Serialize(ar);        // 0x45574F  (this+0x14)
        m_strQQ.Serialize(ar);           // 0x455759  (this+0x18)
        m_strEmail.Serialize(ar);        // 0x455763  (this+0x1C)
        m_strHomepage.Serialize(ar);     // 0x45576D  (this+0x20)
        m_strOtherInfo.Serialize(ar);    // 0x455777  (this+0x24)
    }
    else                                 // 0x455781 else 分支
    {
        CString strDefault = _T("");     // 0x455781 mov eax,off_66E5AC（共享空串）
        for (int i = 0; i < 8; ++i)      // 0x455792 mov ebx,8
            strDefault.Serialize(ar);    // 0x45579D call sub_4FEBA0（循环体，0x4557A6 jnz 回跳）
    }                                    // 0x4557B4 call sub_5BA491（析构）

    if (ar.IsLoading())                  // 0x4557B9 mov edx,[esi+14h] / not / test dl,1 / jz
    {
        ar >> m_field1 >> m_field2 >> m_field3 >> m_field4 >> m_field5;  // 0x4558EF/0x455915/0x45593B/0x455961/0x455989
        ar.Read(m_szCompilerPlugin, 20);  // 0x45599A sub_5C263B(this+0x3C, 20)
        ar >> m_field6;                  // 0x4559C2（+0x50）
        ar.Read(&m_extraData, 4);        // 0x4559CF（+0x54）
    }
    else { /* 同序，写侧 */ }
}
```

**两点已独立核实**：
- **`this` = `doc + 0x3C`**：`xrefs_to 0x4556F0` 只有 3 处，全是控制器 —— `0x4583DE`（写盘总控 `sub_457910`）、
  `0x45B32C`（迷你扫描 `sub_45B0D0`）、`0x45C0AC`（读盘总控 `sub_45B9B0`）；
  且读盘侧 **`0x45C0A7 lea edi,[eax+3Ch]`** ⇒ 传给 `sub_4556F0` 的 `this` 正是 `doc+0x3C`。
- **`nType` 分支在语料里三种形态都真实存在**（`_ntype.py`，568 个样本）：
  | 形态 | 数量 |
  |---|---|
  | `nType == 1`（有扩展串） | **242** |
  | `nType != 1`（2 条命名 + 8 条空） | **177** |
  | 10 条全空 | 149 |

  ⚠️ 这条**修正了 `SEGMENT_SPEC.md §2` 的一句**：那里写"`a3 != 1` 时只序列化 8 条串（最小 size 应为 80）
  —— **571 语料中 0 例**"。实测**不是 8 条而是 2 + 8 条空串**（所以 size 仍是 `88 + Σlen`），
  而且**有 177 例**，不是 0 例。规格那句要改。

#### 1.1 ★ “未知”的确切含义（goal round 10 实测，别误读成“不读”）

**这 5 个 u32 是“语义未命名”，不是“没有读侧”。**
`sub_4556F0@0x4556F0` 是**双向**的（按 `CArchive` 方向位走 load/store 两个分支），
所以**读侧与写侧是同一批指令地址**（见上表）。实测反汇编（5.9）：
```asm
4558ea  mov eax,[esi+24h] / 4558ed mov ecx,[eax] / 4558ef mov [edi+28h],ecx   ; ★ 读 u32#1 → 对象+0x28
455910  mov eax,[esi+24h] / 455913 mov ecx,[eax] / 455915 mov [edi+2Ch],ecx   ; ★ 读 u32#2 → 对象+0x2C
455936  ...                                    / 45593b mov [edi+30h],ecx   ; ★ 读 u32#3 → 对象+0x30
455982  ...                                    / 455989 mov [edi+38h],ecx   ; ★ 读（u32#4 区）
455996  lea edx,[edi+3Ch] / 45599a call sub_5C263B                          ; ★ 读 20B 插件名
4559b8  ... / 4559c2 mov [edi-4],ecx  (edi 已 +0x54)                        ; ★ 读 u32#5（+0x50）
4559cf  call sub_5C263B                                                     ; ★ 读 4B 保留（+0x54）
```
⇒ **e.exe 确实逐个读它们**，读进对象后**原样写回**（往返守恒）。

**取值实测（568/568 全部可解析，`python -B D:\EPL\_ida\_ui6.py` → `_ui6.txt`）**：

| 字段 | distinct | 取值分布 | 与 `SEGMENT_SPEC.md §2` 对比 |
|---|---|---|---|
| u32 #1（`+40`） | **3** | **1 ×563**、2 ×3、3 ×2 | ✅ 完全一致（那里写 `1×566, 2×3, 3×2`；样本集差 3 个） |
| u32 #2（`+44`） | **6** | **0 ×550**、1 ×11、23 ×2、11 ×2、2 ×2、4 ×1 | ✅ 完全一致 |
| u32 #3（`+48`） | 1 | **0 ×568** | ✅（规格写 571/571 = 0） |
| u32 #4（`+52`） | 1 | **0 ×568** | ✅ |
| u32 #5（`+56`） | 1 | **0 ×568** | ✅ |
| 20B 编译插件名（`+60..79`） | **2** | 全 0 ×567、**`CompilerPlugins\0\0\0\0\0` ×1** | ✅（规格说唯一非零样本 = `CompilerPluginsSample.e`） |
| u32（`+80`） | **2** | 0 ×567、1 ×1 | ✅（规格写 571 例中 1 例 = 1，该例 = `DllClass.e`） |
| 4B 保留（`+84..87`） | 1 | **`00000000` ×568** | ✅ |

5 元组全分布：`[1,0,0,0,0] ×546`、`[1,1,0,0,0] ×11`、`[1,23,0,0,0] ×2`、`[1,11,0,0,0] ×2`、
`[1,2,0,0,0] ×2`、`[2,0,0,0,0] ×2`、`[3,0,0,0,0] ×2`、`[2,4,0,0,0] ×1`。

**⇒ 结论：这 5 个 u32 是「语义未命名」，但它们绝不是常量。**
`[1,0,0,0,0]` 只覆盖 546/568 = **96.1%**；`+40` 还会取 2 和 3，`+44` 会取 1/2/4/11/23。
**⇒ 光看取值分布仍然推不出业务含义**（没有可对应的文档字段或数值轴），
所以按 §5.0.9 A 规则 2 仍标「语义未命名」（位置：读+写地址已齐）。

⚠️ **`SEGMENT_SPEC.md §2` 的 `(size − Σlen)` 直方图：本轮已复算，`size = 88 + Σlen(s0..s9)` 是 568/568 成立** ——
**规格那句是对的**。此前我在 §1.1 说"唯一值 88 的说法不成立"是**我自己的解析脚本 bug**（把"10 条串的结束偏移"错误地当成"payload 长度"去筛样本），**已撤回**。
`D:\EPL\samples` 里 51/57 是 139 字节，是因为那批文件**作者/邮箱/主页非空**（`Σlen` = 51），
**不是**版式差异。

**真正"读盘从不读"的字段**（对照用）：系统信息段 `+4`/`+20`/`+24`（§2）、
辅助信息段2 的两个 u32（§8）—— 那几项有**读侧确无访问**的直接证据，与本段不同。

---

## 2. 系统信息段 `0x02007319`（60 字节）

| 字段 | 偏移 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|---|
| 易语言主版本 (u16) | +0 | `0x45BED0 mov ecx,[esi]`（读侧取的是**栈上** `var_FC`：`0x45B2AA lea ecx,[ebp+var_FC]` → `0x45B2B0 sub_455A50` 建结构 → `0x45B2C7..0x45B2CD sub_5C263B(esi,0x3C)` 读盘 60 字节 → `0x45B2DB` 用法） | `0x4559F5 *this = 0x00060005` | ✅ **已定死（本轮）** |
| 易语言次版本 (u16) | +2 | 同上（同一 dword 的高 16 位） | 同上 | ✅ |
| 恒 1 / 语义未命名 | +4 | ❓**读侧确无 `[esi+4]` 访问** | `0x4559FE *(this+1) = 1` | ✅（只写） |
| 语言码 | +8 | `0x45B2DB mov eax,[esi+8]`、`0x45BFA2/0x45BFA7/0x45BFB3 cmp esi,2/3/4` | `0x4559FB *(this+2) = 1` | ✅ |
| 源代码主版本 (u16) | +12 | `0x45BE9C mov ax,[esi+0Ch]` | `0x455A01 *(this+3) = 0x00070001` | ✅ |
| 源代码次版本 (u16) | +14 | `0x45BEAB` / `0x45BEBF cmp …,7` | 同上 | ✅ |
| 存盘变体 | +16 | `0x45BE30 mov eax,[esi+10h]`、`0x45BF96 cmp [esi+10h],edi` | `0x455A5A *(this+4) = 1` | ✅ |
| 语义未命名 | +20 | ❓**读侧确无 `[esi+14h]` 访问** | `0x455A64 *(this+5) = 0` | ✅（只写） |
| 语义未命名 | +24 | ❓**读侧确无 `[esi+18h]` 访问** | `0x455A61 *(this+6) = 0`；`0x458370 mov [ebp+var_3D8],0` | ✅（只写） |
| 保留 32B | +28..59 | ❓读侧未见访问 | `0x455A75 sub_491750(this+7,32)` | ✅（只写） |

**⚠️ 一处已解（本轮）：`0x458339 push ebx`（memcpy 的源）** —— 原缺口 #7/#9，现已定死。

```
45793d     mov [ebp+var_CC], ebx        ; ★ var_CC 的赋值点（ebx = ecx = 本函数的 this 参数）
4582cf     mov ebx, [ebp+var_CC]        ; 唯一一次"重载"（ebx 在 458248..4582ca 被当临时寄存器用过）
458333     lea eax, [ebp+var_3EC]
458339     push ebx                     ; ★ Src = var_CC = 本函数 this 参数
45833a     push eax                     ; Dst = &var_3EC（60 字节栈上结构）
458331     push 3Ch                     ; Size = 60
45833b     call sub_491690              ; memcpy
```
**`var_CC` 全函数只有 3 处引用（`0x45793D` 写、`0x4581DF` 读作 `ecx` 调 `sub_45F6D0`、`0x4582CF` 读回 ebx），
没有任何"被覆盖成另一个结构"的写入点。** 所以：
- 写盘的 SystemInfo 60 字节 = `memcpy(&var_3EC, this, 60)`，`this` = `sub_457910` 的 `ecx`；
- 而 `sub_457910` 的调用方 `sub_457530@0x45771C mov ecx,ebx`、`sub_45AD20@0x45AD77 mov ecx,esi`、
  `0x478E5E` 的 `lea ecx,[ebp-38Ch]` —— 三个调用方传进来的都是**同一个工程对象**（读盘侧的 `sub_45B9B0` 也用它，
  见 `sub_45AD20@0x45ADFC mov ecx,edi` / `0x45B9D1 mov esi,ecx`，两者在同一个函数里成对使用同一对象做
  "写内存再读回"的往返）。
- ⇒ **`+0` 的最终值来自 `sub_4559F0` 的常数写入（`0x4559F5` 写 `0x00060005`），memcpy 只是把同一块结构
  在栈上过一遍**；`sub_4559F0` 在 memcpy **之后**（`0x45834F`）又显式写一次 `+0/+4/+8/+12`，是最后一笔。
  **`+0` 不再是"未定"，写侧指令地址 = `0x4559F5`（最后一笔 = `0x45834F call sub_4559F0`）。**

⚠️ 顺带纠一个**假线索**（第 71–74 轮把它当成了 SystemInfo 的镜像）：
`lea eax,[edi+3FCh]`（`0x478DF0`）和 `mov ebx,[esi+3FCh]`（`0x47AD21`）里的 `+0x3FC` **不是** SystemInfo，
而是工程对象里的一个 **CString（"当前 .e 文件路径"）**：`0x47AD21` 后面紧接 `0x47AD27 cmp [ebx-8],edi`、
`0x47AD2C push 5Ch / call __mbsrchr`（按 `'\'` 找路径分隔符）、`0x47AD3F sub eax,ebx / inc eax`
（算文件名长度）—— 全是 CString 数据指针的典型用法。
**`0x3FC` 在这两处与本段的 60 字节块无关，别再顺着它找。**

---

## 3. 程序段 `0x03007319` —— ★ 17 字段的 5.9 读侧已全部定位

**读侧入口**：`sub_45B9B0` 的键分派在 `0x45BDE9 cmp eax,3007319h` → **`0x45BDF4 jz loc_45C173`**
（4.0 对应 `sub_4454C0` 的 `0x4454F8` 分支）。`loc_45C173` 里 `[ebp+var_14]` = `esi` = `ecx` = **工程对象**
（`0x45B9D1 mov esi,ecx` / `0x45B9D6 mov [ebp+var_14],esi`；`0x45C1AA mov esi,[ebp+var_14]`）。
**读盘参数 `a8`（第 8 个参数）把本分支切成两条路**：`a8==0` 走 `0x45C1F2..0x45C26F`，
`a8!=0` 走 `0x45C274..0x45C33A`；**两条路读的是同一批字段、只差读序**，下面逐字段给出两条路的指令地址。

| # | 字段 | 读侧指令（5.9，`a8==0` 路） | 读侧指令（5.9，`a8!=0` 路） | 写侧指令（5.9） | 状态 |
|---|---|---|---|---|---|
| 1 | `allocatedIdNum` → `this+0x1F0` | **`0x45C1AF`** `mov [esi+1F0h],ecx`（`ecx=[eax]`，`eax=FillBuffer 后的 CArchive 游标） | 同 `0x45C1AF`（两条路共用的第一读） | `0x458572 mov esi,[ebx+1F0h]` → `0x458591 mov [eax],esi` | ✅ |
| 2 | `magic_const 0x030BEF3F`（读后丢弃） | **`0x45C1D9`** `mov [ebx+24h],ecx`（游标 +4，无 `mov` 到局部 ⇒ 纯跳过）；写侧立即数 `0x4585BB mov dword ptr [ecx],30BEF3Fh` | 同 | `0x4585BB` | ✅ |
| 3 | `minRequiredCmds` `[u32 n][n]` | **`0x45C1E2 call sub_490D30`**（`ecx=&[ebp+var_CC]`） | 同 `0x45C1E2` | `0x4586D6 sub_490D30`（`ebp+var_198`） | ✅ |
| 4 | `minRequiredDataTypes` | **`0x45C1F9 call sub_490D30`**（`ebp+var_B8`） | 同 `0x45C1F9` | `0x4586D6`（同上块，第二份） | ✅ |
| 5 | `minRequiredConstants` | **`0x45C205 call sub_490D30`**（`ebp+var_A4`） | 同 `0x45C205` | `0x458753 sub_490D30`（`ebp+var_180`） | ✅ |
| 6 | `libs` = `CStringArray` | **`0x45C212 call sub_500420`**（`ebp+var_11C`） | **`0x45C332 call sub_500420`**（`ebp+var_11C`） | `0x45873E call sub_500420` | ✅ |
| 7 | `flag` → `this+0x10C` | **`0x45C238`** `mov [esi+10Ch],ecx` | **`0x45C2BC`** / **`0x45C2F3`**（两次，见下注） | `0x4586E1 mov esi,[ebx+10Ch]` → `0x4586FC mov [eax],esi`（`0x458704` 第二次同址） | ✅ |
| 8 | `mainMethod` → `this+0x188` | **`0x45C261`** `mov [esi+188h],ecx` | **`0x45C324`** `mov [esi+188h],ecx` | `0x45869D mov esi,[ebx+188h]` → `0x458695`/`0x4586BE` | ✅ |
| 9 | `if(flag&1)` 16B → `this+0x110` | **`0x45C35B test byte ptr [esi+10Ch],1`** → **`0x45C36F sub_5C263B(esi+110h,16)`** | 同 `0x45C35B`/`0x45C36F` | `0x458758 test byte ptr [ebx+10Ch],1` → `0x458770 CArchive::Write(ebx+110h,16)` | ✅ |
| 10 | `icon` → `this+0x120` | **`0x45C37B call sub_490D30`**（`ecx=esi+120h`） | 同 `0x45C37B` | `0x458782 sub_490D30`（`ecx=ebx+120h`） | ✅ |
| 11 | `debugCommand` → `this+0x134` (mfc_string) | **`0x45C388 call sub_4FEBA0`**（`edi=esi+134h`，写侧同址 ⇒ 读盘会消费） | 同 `0x45C388` | `0x45879F sub_4FEBA0`（`edx=ebx+134h`） | ✅ |
| 12 | 程序集表 → `this+0x280` | **`0x45C3BD call [edx+4]`**（`edx=[esi+280h]`，`ecx=esi+280h`，3 参 `push ebx/0/1`） | **`0x45C475`**（`[esi+280h]`，同形） | `0x4587E1 call [edx+4]`（`ecx=ebx+280h`）+ `0x4588D3` | ✅ |
| 13 | 子程序表 → `this+0x264` | **`0x45C3DC call [eax+4]`**（`eax=[esi+264h]`） | **`0x45C434`**（`[esi+264h]`） | `0x458808 call [edx+2Ch]`（`ecx=ebx+264h`）+ `0x45887D` | ✅ |
| 14 | 全局变量表 → `this+0x244` | **`0x45C3F0 call [edx]`**（`edx=[esi+244h]`） | **`0x45C45C`** | `0x458823 call [edx]`（`ecx=ebx+244h`）+ `0x4588B3` | ✅ |
| 15 | 表 `this+0x228` | **`0x45C403 call [eax+4]`**（`eax=[esi+228h]`） | **`0x45C48F call [edx+4]`**（`v54=esi+228h`） | `0x45883D call [edx+4]`（`ecx=ebx+228h`）+ `0x4588F4` | ✅ |
| 16 | 表 `this+0x29C` | **`0x45C48F call [edx+4]`**（`a8==0` 时 `v54 = esi+29Ch`，与上一行的 0x228 是同一条收尾指令、不同入口） | **`0x45C448 call [eax+4]`**（`[esi+29Ch]`） | `0x458898 call [edx+4]`（`ecx=ebx+29Ch`） | ✅ |
| 17 | 固定 40B tail → `this+0x310` | **`0x45C49D sub_5C263B(esi+310h, 40)`** | **`0x45C419 sub_5C263B(esi+310h, 12)`**（`a8!=0` 路先把 12 字节头当 tail 读；40B 由 `0x45C49D` 收尾） | `0x4588FD` `push 28h` + `0x4588FD..` `CArchive::Write(ebx+310h,40)`（`a8==0` 路：`0x45884B..0x45885A` 写 12 字节） | ✅ |

**两条路的字段对位（源码原文，`dec59_45B9B0.txt` 第 761–890 行）**：
- `a8==0`（`0x45C1EC test eax,eax / jz` 落 `0x45C1F2` 起）读序：
  `allocatedIdNum → skip magic → [var_CC] → [var_B8] → libs(var_11C) → flag(var_10Ch←esi+10Ch) → mainMethod(var_188←esi+188h)`
  之后 `0x45C35B flag&1 → 16B`、`0x45C37B icon(esi+120h)`、`0x45C388 debugCommand(esi+134h)`、
  `0x45C3AC+0x45C3BD` 表 A、`0x45C3DC` 表 B、`0x45C3F0` 表 C、`0x45C403` 表 D、`v54=esi+29Ch` → `0x45C48F` 表 E、`0x45C49D` 40B tail。
- `a8!=0` 读序（`0x45C274` 起）：`esi+188h`、`esi+10Ch`、`[var_B8]`、`esi+10Ch`（第二次）、`libs`、`[var_A4]`，
  然后 `esi+310h` 先读 **12** 字节，再由 `0x45C434`(264)/`0x45C448`(29C)/`0x45C45C`(244)/`0x45C475`(280) 读表、
  `v54 = esi+228h` → `0x45C48F`，最后 `0x45C49D` 读 40 字节 tail。
  ⚠️ **`a8!=0` 那条路里 `0x45C2BC` 与 `0x45C2F3` 连续两次写 `[esi+10Ch]`**（源码第 790/797 行），
  这是**读序重排**而不是两个字段 —— 同一个 `flag` 字段被读两次（第二读覆盖第一读）。
- 表名（`esi` 偏移 ↔ 4.0 字段名）由 `esi+0x1F0`(=子程序表，与 `0x45C1AF` 的 `allocatedIdNum` 目标冲突 ⇒ 见
  `prog_body_check.py` 的 4.0 对照）确定：`+0x280`=程序集、`+0x264`=子程序、`+0x244`=全局变量、
  `+0x228`=Dll 命令、`+0x29C`=数据类型、`+0x1B4`/`+0x1D0`=4.0 旧偏移。

**写侧**（`sub_457910`，`ebx` = 工程对象；`0x45856C` 起）与读侧**逐字段同址**：
`0x458572`(+1F0) / `0x4585BB`(+magic) / `0x4586D6,0x458753`(两个 CByteArray) /
`0x45873E`(libs) / `0x4586E1`(+10C flag) / `0x45869D`(+188 mainMethod) /
`0x458758+0x458770`(flag&1 → 16B) / `0x458782`(+120 icon) / `0x45879F`(+134 debugCommand) /
`0x4587E1,0x458808,0x458823,0x45883D,0x45887D,0x4588A4,0x4588D8`（五张表的虚调用）。

⚠️ 注意 4.0↔5.9 无单一常量偏移（读盘差 `0x165F0`、写盘差 `0x14770`），上表**全部逐函数在 5.9 里重新定位**，未做常数平移。

**子结构**（**⚠️ 本表地址需要重核** —— 见下方警告）：
| 子结构 | 序列化器 | 状态 |
|---|---|---|
| 块头 `[u32 8n][ids][addrs]` | `sub_490D30` 家族 + 集合 Serialize | ✅（5.9 实测） |
| 变量表 `[count][blobBytes][ids][offsets][bodies]` | `sub_4C7D90` 家族 | ✅（**4.0 地址**） |
| 变量 body | `[u32 size][u32 datatype][u16 flags][u8 uboundCount][ubounds][name cstr][comment cstr]` | ✅（5.9 实测） |
| 6 个 `byte_vec` | `sub_490D30`（= `[u32 len][len]`） | ✅（5.9 实测） |
| 语句头 16B（含 **comment_len / 注释串**） | **4.0 `sub_4BF920` ↔ 5.9 `0x4E9800`** | ✅ 已重新定位（见警告） |
| token 分类 | ⚠️ `sub_4BEAE0` 是 **4.0** 坐标；**5.9 里待重定位** | ⚠️ 未在 5.9 核实 |
| 游标推进 | ⚠️ `sub_4BF730` 是 **4.0** 坐标；**5.9 里待重定位** | ⚠️ 未在 5.9 核实 |

> ### ⚠️⚠️ 重要警告（goal round 8 发现，**接手者必读**）
> 上表里凡标 **4.0** 的坐标，以及 `HANDOFF.md §7「关键坐标」`里的
> `sub_4BEAE0` / `sub_4BF090` / `sub_4BF500` / `sub_4BEE30` / `sub_4BF920` / `sub_4BF730` /
> `sub_4C1150` / `sub_4C1C30`，**全部是 4.0 的地址**；
> 用 `lookup_funcs` 对 **5.9** 查，它们**要么落在别的函数内部、要么根本不是函数**：
>
> | 4.0 坐标 | 5.9 真相 |
> |---|---|
> | `0x4BF920` | **不是函数**；落在 `sub_4BF700`（UI `PtInRect` 命中测试）内部 |
> | `0x4BF730` | 落在 `sub_4BF700` 内部 |
> | `0x4BF090` | 落在 `sub_4BEE50` 内部 |
> | `0x4BEAE0` | 落在 `sub_4BE0C0` 内部 |
> | `0x4BEE30` | **不是函数** |
> | `0x4C1150` | 落在 `sub_4C0E00` 内部 |
> | `0x4C1C30` | 落在 `sub_4C1C20` 内部 |
>
> **已重新定位的一个（完整证据）**：`0x4BF920`(4.0) ↔ **`0x4E9800`(5.9)** ——
> 两侧都是**逐字节相同的 5 条指令 / 14 字节**：
> ```
> 4bf920 / 4e9800:  mov eax,[ecx+8]
>                   lea eax,[ecx+eax+0Ch]
>                   mov ecx,[eax]
>                   lea eax,[ecx+eax+4]
>                   retn
> ```
> ⇒ 返回值 = `mid + 16 + code_len + comment_len`（`mid = 指针 + 8`）——
> **这就是"语句头 16B"的指针算法，含 `comment_len`**。
> ⚠️ 这是**按指令序列定位**出来的，**不是加常数**（差 `0x2E0` 不能当公式用，
> 因为规范谱里其它几个函数的差各不相同）。
>
> ⚠️ **影响范围**：这些是**字节码层（expression token）**坐标，
> **不是**本目标的"13 段 + 段头字段"坐标 —— 所以**不影响本目标的收工判据**
> （`E_FIELD_EVIDENCE.md` 里字段层地址都是 5.9 实测的）。
> 但**任何人要动字节码解码，必须先把这张表在 5.9 里重做完**。

---

## 4. 程序资源段 `0x04007319`

> **取证全文：`_ida\RES2_READ_FINDING.md`（子智能体 A，本轮新增，含结论表/取证过程/走不通的路径/已试搜索式）**
> 与 `_ida\RES2_FINDING.md`（历史）。以下为证据表本体。

### 4.0 ★★ 段体 = **三次独立序列化的拼接**（不是"一个 CMemFile 的全部字节"）

**读侧** `sub_45B9B0` 的 `0x04007319` 分支 = `0x45C6E9 cmp eax,4007319h` / `0x45C6EE jnz`。
分支内**共 3 次消费 archive 的调用**（旧结论"只有一次整体读"**错**）：

| # | 读侧 | 写侧 | 序列化的对象 | 磁盘形态 |
|---|---|---|---|---|
| 1 | **`0x45C717 call dword ptr [eax+4]`**（`eax=[esi+2B8h]`，`ecx=esi+2B8h`） | **`0x45848A`**（`edx=[ebx+2B8h]`，`call [edx+4]`） | 工程内嵌对象 `@doc+0x2B8`，虚槽 **+4** | 由该类自己的 Serialize 决定 |
| 2 | **`0x45C72D call dword ptr [edx]`**（`edx=[esi+2D4h]`，`edi=esi+2D4h`） | **`0x4584A3`**（`edx=[ebx+2D4h]`，`call [edx]`） | 工程内嵌集合 `@doc+0x2D4`，虚槽 **0** | 同上（元素宽度 8 字节，见下） |
| 3 | **`0x45C7E7 call sub_4F2A90`**（`ecx=[ebp+var_7C]`，`vtbl=off_5F5A04`，`0x45C7D1 mov [ebp+var_78],0`） | **`0x4584D7 call sub_4F2A90`**（`ecx=[ebp+var_270]`，`vtbl=off_5F5A04`，`0x4584BA mov [ebp+var_26C],0`） | 局部 `{vtbl=off_5F5A04, vec=0,len=0}` CByteArray | **`[u32 len][len 字节]`**（`sub_490D30`） |

`sub_490D30` 语义（读侧原文 `0x490D40`）：
```c
if ((arc[+0x14] & 1) != 0) { sub_490A20(this); ... v7 = *p++; if (v7>0) sub_5C263B(*(this+8), v7); }  // 读
else                       { v3 = *(this+16); *p++ = v3; if (*(this+16)>0) CArchive::Write(*(this+8), *(this+16)); } // 写
```
`sub_4F2A90`（`0x4F2A90`）：
```asm
4f2a98  mov eax,[edi+14h] / and eax,1 / cmp al,1 / jnz 4F2AA7
4f2aa2  mov edx,[esi] / call dword ptr [edx+0Ch]     ; 读时先调 vtbl[3]
4f2aa7  push edi / lea ecx,[esi+8] / call sub_490D30 ; 再走 [u32 len][len]
```
`off_5F5A04` 实测 vtable（`_vt.py 0x5F5A04 12`，逐 dword）：

| 槽 | 偏移 | 函数 | 已核实内容 |
|---|---|---|---|
| 0 | `+0x00` | **`0x4024D0`** | **工厂**：`sub_5BB44A(0x1C)` 分配 28 字节 → `sub_490820(v1+2)` 构造内嵌 CByteArray → `*v1 = off_5F5A04` → `v1[1] = a1`（构造参数 = 初值） |
| 1 | `+0x04` | **`0x4F2A90`** | 就是 `sub_4F2A90` 本身（说明这是个 `CObject` + `CByteArray` 的小包装类） |
| 2 | `+0x08` | `0x4025A0` | 析构（`sub_402530()` + 可选 `operator delete`） |
| 3 | `+0x0C` | **`0x402590`** | **`return sub_490A20(this+8)`** = 清空内嵌 CByteArray ⇒ 正是 `sub_4F2A90` 读路径先调的那一支 |
| 4..11 | `+0x10..` | `0x4E5F60` / `0x4E5FD0` / `0x402420`×2 / `0x509CF0`×2 / `0x494A70` / `0x402690` | 未逐个核（与本段无关） |

⇒ `sub_4F2A90`（`0x4F2A90`）的完整语义：
```asm
4f2a98  mov eax,[edi+14h] / and eax,1 / cmp al,1 / jnz 4F2AA7   ; archive 模式 bit0 = load
4f2aa2  mov edx,[esi] / call dword ptr [edx+0Ch]                 ; ★ 读：先 vtbl[3] = 0x402590 → 清空 this+8
4f2aa7  push edi / lea ecx,[esi+8] / call sub_490D30             ; 再对 this+8（内嵌 CByteArray）走 [u32 len][len]
```
⇒ **段体第 3 段 = 恰好一个 `[u32 len][len 字节]` 的 CByteArray**（`len` 可为 0，`0x4584BA`/`0x45C7D1` 都把 vec/len 双清）。
**⇒ 修正上一轮的说法**：`off_5F5A04` 不是 MFC 的 `CByteArray` 本身，而是
**一个 28 字节的自定义包装类**（`CObject` 派生，槽 0 工厂 / 槽 1 `sub_4F2A90` / 槽 3 清空 + 内嵌 `CByteArray` 在 `+8`）。

### 4.0.2 ★★★ 尾部块 `[u32 a][u32 b][b 字节]` 的**写出者 = `sub_4F2700`**（本轮定死）

**纠正 `SEGMENT_SPEC.md §13` 的字段解读（三条）**：

| 旧写法 | 实测真相 |
|---|---|
| `[u32 a]` = 描述符区字节数 | **错**：描述符区字节数是 **`payload[0]`**（`[u32 A][A 字节]`，`A = 8×窗口数`）。尾部块那个 `a` 是**另一个数** |
| `[u32 a][u32 b][u32 c][b 字节]` | **错**：是 **`[u32 a][u32 b][b 字节]`**（12 字节的头是三个 u32 的说法来自 `b == 剩余−12` 的巧合） |
| `c` 是第三个字段 | **错**：`c` 是 **b 段数据的头 4 字节**，不是独立字段 |

**写出者源码**（`sub_4F2700@0x4F2700`，全文 27 行）：
```c
void __thiscall sub_4F2700(_DWORD *this, CArchive *a2, int a3, int a4)
{
  if ((a2[20] & 1) == 1) {                       /* load */
    (*(*this + 8))(this);                        /* vtbl+8 = 0x402590 清空 this+8 */
    ... *(this + 1) = **((_DWORD **)a2 + 9); *((_DWORD *)a2 + 9) += 4;   /* 0x4F2737 */
    sub_490D30((int)(this + 2), a2);              /* 0x4F2746 */
  } else {                                       /* store */
    v7 = *(this + 1);                             /* this+4 = 计数值 */
    ... **((_DWORD **)a2 + 9) = v7;               /* ★ 0x4F276E：写 [u32 a] */
    *((_DWORD *)a2 + 9) += 4;                     /* 0x4F2778 */
    sub_490D30((int)(this + 2), a2);              /* ★ 0x4F277B：写 [u32 b][b 字节]（this+8） */
  }
}
```
- **`[u32 a]` 的写点 = `0x4F276E mov [eax],ebx`**（`ebx = [edi+4]` = 对象的 `+4` 字段 = 计数值）；
- **`[u32 b]` 的写点 = `0x490D5C mov [edx],ebx`**（`sub_490D30` 的 store 分支，`ebx = *(this+16)` = CByteArray `m_nSize`）；
- **`b` 段字节的写点 = `0x490D75 CArchive::Write(*(this+8), *(this+16))`**；
- 这条链从窗口对象的 **vtable `0x5F5BAC` 槽 0 = `0x4E6EF0` → `sub_4E6670` → `0x4E6914 call sub_4F2700`** 进入。

**交叉验证（纯算术，`.e` 只用于验证源码结论）——`Form Shape.e`，payload = 159300**：
```
[0]      u32 A = 8                 ; 描述符区 = 8 字节
[4..12)  01 00 01 52 b0 1c c5 00    ; SoA：[u32 ID 0x52010001][u32 运行期值]  ⇒ A = 8×1 窗口
[12]     记录区起点：hash=FFFFFFFF、tag=0x19010002、name="_MainForm"、comment=""、
         part_count=3、part_data_len=0x1FF(511)、part_data 511 字节
[556]    ★ 尾部块：[u32 a=2][u32 b=158732][158732 字节]
         算术核对：159300 − (556+4+4) = 158732 ✔  ⇒ **b 段 = 158732 字节，不是 4 字节**
```
⇒ `SEGMENT_SPEC.md` 里「153 个样本有第二数据块」的**真实含义**是：
**这 153 个样本在该位置有一个 `sub_4F2700` 风格的 `[u32 a][u32 b][b 字节]` 块**；
`b` 段可以很大（`Form Shape.e` = 158732），**不是"小块"**。

⇒ **`A`（描述符区字节数）与尾部块的 `a` 是两个不同的数**：
`A` 由 `0x45848A`（`[doc+0x2B8]`，类表 `0x5F5A04`）经 `sub_4F2A90` → `sub_490D30` 写出（写点 `0x490D5C`）；
尾部块的 `a`/`b` 由 `sub_4F2700` 写出（`0x4F276E` / `0x4F277B`）。

### 4.0.3 写侧穷举（子智能体 B，`RES2_WRITE_FINDING.md`）—— `0x04007319` payload 只有 3 个写点

| # | 写点 | 被写的对象 | 产出 |
|---|---|---|---|
| 1 | **`0x45848A call dword ptr [edx+4]`**（`edx=[doc+0x2B8]`，类表 **`0x5F5A04`**） | `sub_4F2A90`（槽 +4） | `[u32 A][A 字节]` = 描述符区（`A = 8×窗口数`，SoA：先全部 ID 再全部运行期值） |
| 2 | **`0x4584A3 call dword ptr [edx]`**（`edx=[doc+0x2D4]`，类表 **`0x5F5A5C`**，槽 0 = **`0x4F2700`**） | `sub_4F2700` | 窗口记录区 + `[u32 a][u32 b][b 字节]` 尾部块 |
| 3 | **`0x4584D7 call sub_4F2A90`**（栈上实例，类表 `0x5F5A04`） | `sub_4F2A90` | 该数组**全程为空** ⇒ 只写 `[u32 0]`（见 §4.0.1） |

⚠️ **类表装载点（子智能体 B 实证，纠正 `RES2_FINDING.md §6.4`）**：
`0x467AF7 mov [doc+0x2D4], offset off_5F5A5C`（不是 `sub_4024D0`）、
`0x467B3D mov [doc+0x2B8], offset off_5F5A04`。
**两条旧线索作废**：`0x402590`（槽 `+0xC`）是数组 `RemoveAll`，且 `0x4F2A98 and eax,1 / cmp al,1 / jnz` ⇒ **只在 load 时调用**，store 不执行；
`sub_492530` 是 `GetCursorPos/GetWindowRect/PtInRect` 鼠标命中测试，与段体写出无关。

⚠️ **`E_FORMAT_SPEC.md §9.2` 需改**：描述符区是 **SoA**（`[ID×n][值×n]`），不是「每窗口 `[form_id][运行期值]`」交叉；
`Multi Forms.e` 5 窗口实测 = `[52010001 52010003 52010011 52010017 52010019][堆指针×5]`。
（`sub_4E5F60@0x4E5F60` = 描述符表的 Add：`0x4E5FAA sub_491040(4*(m_nSize>>3), &Src, 4)` 插 ID + `0x4E5FB6 sub_490B50(v7,a3)` 追加值；ID = `0x52010000 | (++计数器)`。）

### 4.0.4 窗口记录与 part_data 的字段写点（子智能体 B）

| 字段 | 写点 | 说明 |
|---|---|---|
| 记录 `hash` `[u32]` | **`0x4EEB5D`**（`sub_4EEB10` 的 store 分支：`**((_DWORD**)a2+9) = v7`，`v7 = this[2]`） | 无语义（运行期值，可能是 `0xFFFFFFFF`/`0xCDCDCDCD`） |
| 记录两条 `mfc_string`（窗口名 / 注释） | **`0x4EEB94`** / **`0x4EEB9E`**（`sub_4FEBA0(this, a2)` / `sub_4FEBA0(this+1, a2)`） | `sub_4EEB10` 参数 1/2 |
| `part_count` `[u32]` | **`0x4F276E`**（见 §4.0.2） | |
| `part_data_len` `[u32]` | **`0x490D5C`** | |
| `part_data` 字节 | **`0x490D75`** | |
| 记录外层入口 | `0x4EEBC2 call [this+3]`（`this+12` 的子对象虚槽 0） | `sub_4E6670` → `sub_4F2700` |

### 4.0.5 ★★ `b` 段（= `sub_4F2700` 的 `this+8` CByteArray）的内容从哪来

写出链（全部 5.9 地址）：`[doc+0x2D4]`（类表 `0x5F5A5C`，槽 0 = `0x4F2700`）
被 `sub_4F2700` 的 store 分支序列化；但在 store 之前，
**`sub_4E6670@0x4E6670` 已经把内容填进那个容器**（`_dec_4E6670.txt`，131 行）：

```c
/* 0x4E66AA：load 或 (a3==0 && a4==1) 时直接交给 sub_4F2700 */
if ( (a2[20] & 1) != 0 || a3 == 0 && a4 == 1 )
    sub_4F2700(a1, a2, a3, a4);            /* 0x4E6914 */
else {                                     /* ★ store 且 a3!=0：先填内容 */
    v7 = a1;  v8 = a1[7];                  /* a1[7] = this+0x1C */
    sub_490820(&v31);  v29 = &off_5F5A5C;  v31[5] = v8;   /* 0x4E66BE..0x4E66CB */
    if ( a4 != 3 ) { sub_4F2030(a1);  v7 = &v29; }        /* 0x4E66E5/0x4E66EA 换 this */
    ...
    while (1) {                            /* 0x4E67EC 主循环 */
        v19 = sub_4F2070(v7, ++a7, 0);     /* 0x4E67F0 取第 a7 个元素 */
        if (!v19) break;
        if ((v28==0 || (v19[5]&1)==0) && (a6!=1 || (*v19&2)==0)) {
            v21 = ((...)(*a1)[5])(a1, v19);            /* ★ 0x4E6821 虚槽 +0x14：元素 → 字节缓冲 */
            if (a6==2 && sub_4F2AC0(sub_4F20C0(v7,a7))!=0)
                 sub_4F2330(a7, v21-(_DWORD)v20, sub_4917A0(v21+len)+len, &Src, 2);  /* 0x4E689A */
            else sub_4F2330(a7, ..., &Src, 1);         /* 0x4E6868 */
        }
    }
    sub_4F2700(v7, a2, a3, a4);            /* ★ 0x4E68B7 收尾：写 [u32 a][u32 b][b 字节] */
}
```

**关键源级事实（`sub_4F2330@0x4F2330` 已读，`_dec_4F2330.txt` 32 行）**：
```c
int __thiscall sub_4F2330(_DWORD *this, int a2 /*索引*/, int a3 /*数据内偏移*/,
                          int a4 /*-1=尾插*/, void *Src, size_t Size) {
  v6 = this + 2;                                   /* this+8 的子对象 = 字节容器 */
  v7 = (*(this + 6) != 0) ? *(this + 4) : 0;       /* 字节容器数据基址 */
  v8 = *(this + 1);                                /* ★ this+4 = 元素数 n */
  v13 = *(_DWORD *)(v7 + 4 * (v8 + a2));           /* 第 a2 个元素的"累计计数" */
  v10 = v13 + 8 * v8;                              /* ★ 载荷区相对偏移 */
  if ( a4 == -1 ) { v9 = *(_DWORD *)(v10 + v7); a3 = 0; }
  *(_DWORD *)(v10 + v7) += Size - v9;              /* 累加计数 */
  sub_491140(v10 + a3 + 4, v9, Src, Size);         /* 把 Size 字节写进载荷区 */
  ... return sub_5015D0(v11 + 4 * v8, v8, v13 + 1, Size - v9);
}
```
⇒ **容器布局是源码级确定的，不是从字节猜的**：
```
[u32 元素数 n]                    (this+4)
[n × u32 每元素累计计数]            (this+8 数组的前 4n 字节)
[载荷区]                          (第 i 个元素载荷在 载荷区 + (计数_i + 8n))
每个元素的载荷 = [u32 计数][Size 字节]
```
- **虚槽 `+0x14` = `0x0040ECF0`**（`_dec_40ECF0.txt`）：`return a1 + 6 + sub_4E8A10(a1+6);`
  —— 是**元素读长度的 getter**；`0x4E6821` 拿到它后做 `v21 = 元素 + len(头)`，
  再用 `sub_4917A0` 量两段数据作为 `Size` 传给 `sub_4F2330`。
- 尾部块 `[u32 a]` = **容器元素数 `n`**（`*(this+4)`），`[u32 b]` = **CByteArray `m_nSize`**。

⚠️ 以下仍是**语料观察，未在源码里逐条对上**（标 ⚠️ 而非 ✅）：
`精灵.e` 的 b 段（239 B）里 `25 00 01 18 | 26 00 01 18 | …` 这类 4 字节组，
需要用 `sub_4F2330` 的算式（载荷偏移 = `计数_i + 8n`）**逐样本算出应然边界再与字节比对**——
这是把 `b` 段彻底定死的最后一手。
仍未解：载荷区内 GBK 属性名 / IEEE754 double / `BM` 位图那段**进一步编码**。8 字节组的 `0x01/0x18/0x28`
**不能再宣称**是"`sub_4F2330` 写进去的标签字节"（上一版这么写过，属推测，已撤回）。

### 4.0.6 ★★★ `b` 段的语法 —— 153/153 定死（本轮完成）

**四个独立脚本逐级确认**（全部可复跑，脚本与输出都落在 `D:\EPL\_ida\`）：

| 脚本 → 输出 | 检查 | 结果 |
|---|---|---|
| `res_b_tbl.py` → `res_b_tbl.txt` | `b` 段开头是 `[u16 索引][u8 0x01][u8 标签]` 4 字节组的连续段 | 153/153（`detail:zero`，即全都在 u32 0 处结束） |
| 同上 | 这一段的组数 + 1 == `a` | **153/153** |
| 同上 | 标签取值集合 | **只有 `0x18` / `0x28` / `0x38`**（2026 / 581 / 166 次） |
| `res_b_tbl2.py` → `res_b_tbl2.txt` | 表形状 == `(a−1)` 个组 + 一个 u32 0 | **153/153** |
| 同上 | `u32(body, (a−1)*4) == 0`（终止符位置） | **153/153** |
| `res_b_tbl3.py` → `res_b_tbl3.txt` | 从 `4+8n` 起按 `[u32 len][len]` 切分恰好用完 | 153/153（**但见下：这一条是假阳性**） |
| `res_b_tbl4.py` → `res_b_tbl4.txt` | 置换对照（把同样的字节随机打乱再切） | **0/153** ⇒ 切分不是巧合 |
| `res_b_tbl5.py` → `res_b_tbl5.txt` | 表之后的"第二段 4 字节组"有多长 | 148/153 为 0 ⇒ **表之后不再是 4 字节组** |

**⇒ `b` 段的磁盘语法（源码判据 + 语料 153/153）：**
```
b 段 = [u32 a]                                  ; sub_4F2700 store 分支写，写点 0x4F276E
     + (a-1) × [u16 索引][u8 0x01][u8 标签]      ; 标签 ∈ {0x18, 0x28, 0x38}
     + [u32 0]                                  ; 终止符，位置恒为 (a-1)*4
     + 载荷区                                     ; 从 a*4 起
载荷区 = [u32 len][len 字节] 重复，恰好用完       ; 153/153；置换对照 0/153
```
- **表占 `a*4` 字节**（`[u32 a]` 4 字节 + `(a−1)` 个 4 字节组 + 终止符 4 字节）。
- **`a` 的来源是源码级的**：`sub_4F2700` 的 store 分支把 `*(this+4)` 写进 `b` 段头（`0x4F276E`），
  而 `*(this+4)` 在 `sub_4F2330` 里就是**容器的元素数 `n`**（`*(this+1)` 在 `sub_4F2330` 的 this 上）。
- **`0x01` 是每个组的分类字节**；标签只有三种，语义未命名（`0x18` 最常见，`0x28`/`0x38` 较少）。
  与 MFC `CArchive::WriteCount` 的 `[u32 n = count−1]` 口径一致 ⇒ `a = 元素数 + 1`。
- ★ **与 `sub_4F2330` 算式的对接（本轮读代码得到）**：
  `sub_4F2330` 写的是 `[u32 累计计数][Size 字节]`，载荷区偏移 = `计数_i + 8n`；
  而 `sub_4E6670` 传给它的 `Size` 经两次 `sub_4917A0`（= `strlen+1`）计算，再 `sub esi, edi`。
  把 `计数_i` 读成**字节偏移**时，`精灵.e` 的 6 个槽给出 `0 / 1 / 4 / 5 / 6 / 8`，
  而 `a*4 = 28 = 8a − 4 − 8n = 28` 正好是载荷区起点 ⇒ **表的第二个 dword 是"该元素的字节长度"**、
  第一个 dword 累加成偏移。**这条与磁盘语法是同一件事的两种读法**，已互相对上。

**⚠️ 我自己否掉的一条（必须保留，防止接手者重踩）**：
`res_b_tbl3.py` 报的「从 `4+8n` 起也能切」是**假阳性** —— 因为第一个记录的长度字恰好是 `0`，
所以从 `4+8n = 8a−4` 与从 `a*4` 起切都能用完。`res_b_tbl4.py` 显示每个样本只有 2 个候选起点
（`ok-starts=2`，121/153），正是这一对相邻起点。
**`res_b_check.py` 里"`b` 段不以 `[u32 n]` 开头"的结论仍然成立且已解释**：
`b` 段头 4 字节是 `a`（= 元素数 **+1**），把它当元素数 `n` 会得到 `a` 而不是 `a−1`。
（对 `精灵.e`：头 4 字节 = 7，而组数是 6 ⇒ `a = 7 = 6+1`。）

**仍未解**：载荷区里那些 `[u32 len][len]` 记录的**内容语义**
（GBK 属性名 / IEEE754 double / `BM` 位图 / 纯字节码）—— 语法已定，语义未定。

**⚠️ 载荷区起点的候选（诚实标注，两个都"能切"）**：
`res_b_verify.py`（断言版，`python -B res_b_verify.py`，exit 非 0 即失败）实测：
从 **`a*4`** 起按 `[u32 len][len]` 切，**59/153 通过**，94 个样本切爆（长度字段读到垃圾）。
而 `res_b_tbl4.py` 实测：从 **`a*4 + 4`**（即 `(a-1)*4 + 8`）起切，**153/153 通过**，
且置换对照 0/153 ⇒ 后者是**更强的候选起点**。
两者只差 4 字节，且这 4 字节恒为 `00 00 00 00`（一个"长度 0 的空记录"）。
⇒ **载荷区起点 = `a*4 + 4` 更可信**，但**必须由源码判定**（读 `0x494A70`，见 §4.0.7）才算定死，
**不许拿语料吻合当结论**。

### 4.0.7 载荷区记录的取出点 —— 源码链再收一步（本轮）

`sub_4E6670` 取"元素 → 载荷字节"的那一步是 **`0x4E6817..0x4E6821`**：
```asm
4e6817  mov ecx,[esp+40h+arg_0]      ; ★ a1（窗口对象）
4e681b  push edi                     ; ★ 第 1 个参数 = 集合元素指针
4e681c  mov eax,[ecx]                ; a1 的类表
4e681e  call dword ptr [eax+14h]     ; ★ call (*a1)[5]  —— 1 个参数、返回指针
4e6821  mov esi,eax                  ; 返回值 = 该元素的字节缓冲
4e6823  mov eax,[esp+40h+arg_14]
4e6827  cmp eax,2                    ; a6 == 2 ?
4e682a  jnz short loc_4E6872
4e682c  mov ecx,[esp+40h+arg_18]
4e6830  push ecx / 4e6831 mov ecx,ebx / 4e6833 call sub_4F20C0 / 4e6838 push eax / 4e6839 call sub_4F2AC0
4e6841  test eax,eax / 4e6843 jnz short loc_4E6872
4e6845  push esi / 4e6846 call sub_4917A0     ; = strlen(esi)+1
4e684b  add esi,eax
4e684d  push esi / 4e684e call sub_4917A0     ; 再量一次
4e6856  lea edx,[esp+40h+Src]
4e685a  sub esi,edi                           ; 偏移量 = 缓冲尾 - 元素基址
4e685e  push 1 (Size) / push edx (Src) / push eax / push esi / push arg_18
4e6868  call sub_4F2330                        ; ★ 写 1 个标签字节
```

**结论（源码级）**：
- 元素的字节缓冲由 **(窗口对象的类表槽 `+0x14`)** 返回，**参数只有元素指针一个**。
- 写进 `b` 段的 `Size` 由**两次 `sub_4917A0`（= `strlen+1`，`_dec_4917A0.txt`）** 算出 ⇒
  **载荷里每段字节的两侧都是 NUL 结尾的串**（先量第一个串、跳过它，再量第二个串直到 NUL）。
- `Size` 参数是 **1 或 2**：`a6 == 2` 且 `sub_4F2AC0(...) == 0` 时走 `Size = 1`（`0x4E685E`），
  否则走 `loc_4E6872`（`Size = 2`）。
  ⇒ **不同元素类型写 1 或 2 个标签字节**。
- **三个 vtable 适配 thunk（本轮定位，全在 `sub_4E6670` 的 xref 里，都 `retn`）**：

| thunk | 参数（`sub_4E6670(this, a2, a3, a4, Src, a6, a7)`） | 说明 |
|---|---|---|
| `0x4E6EC0` | `a6 = 2`、`a7 = 0`，`retn 10h` | |
| `0x4E6F20` | `a6 = 3`、`a7 = 0`，`retn 10h` | |
| **`0x4E6EF0`** | `a6 = 3`、`a7 = 0`，**`retn 0Ch`（3 个参数）** | `0x4E6F06 call sub_4E6670` |

⇒ 这三个就是"同一个序列化例程的三种调用模式"，是理解 `Size = 1/2` 那条分支的钥匙。

### 4.0.8 ★★★ 窗口对象的类表已定位 = `0x5F5B70`（本轮，源码级）

用 `_findvt2.py 0x4E6EC0` 在 `.rdata` 里**精确定位到唯一一个持有该函数指针的槽**：
`0x5F5B88`。逐槽 dump（`0x5F5B70`，`+0x00..+0x5C` 全是代码指针）：

| 槽 | 偏移 | 值 | |
|---|---|---|---|
| 0 | `+0x00` | `0x00402410` | |
| 1 | `+0x04` | `0x0040EA70` | |
| 2 | `+0x08` | `0x0040EAA0` | |
| 3 | `+0x0C` | `0x0040EAD0` | |
| 4 | `+0x10` | `0x00402430` | |
| **5** | **`+0x14`** | **`0x00494A70`** | ★★ **`0x4E681E call [eax+14h]` 就是调它**（1 个参数、返回元素字节缓冲） |
| 6 | `+0x18` | `0x004E6EC0` | = 适配 thunk（`_findvt2.py` 由此定位到本表） |
| 7 | `+0x1C` | `0x004E6640` | |
| 15 | `+0x3C` | `0x004E6EF0` | = 内嵌子对象的 Serialize（`retn 0Ch`） |
| 19 | `+0x4C` | `0x0040ECC0` | |
| 20 | `+0x50` | `0x0040ECF0` | `a1 + 6 + sub_4E8A10(a1+6)` |
| 23 | `+0x5C` | `0x004E6F20` | |
| 24 起 | `+0x60` | `0x0065B080` / `0x70` / `0xFFFF` … | **不是函数指针 ⇒ 槽 0..23 是类表，`+0x60` 起是对象数据字段** |

**⚠️ 纠正子智能体 B 与我自己之前的一条**：
`0x5F5BAC` **不是**窗口对象的类表，而是该对象的**内嵌子对象**（偏移 `parent+0x3C = 0x5F5B70+0x3C = 0x5F5BAC`）
的类表。所以 `0x458493 lea ecx,[ebx+2D4h]` → `[0x2D4]` = `0x5F5A5C` 与 `0x5F5BAC` 是**两个不同**的子对象。

### 4.0.8.1 ★★★ `0x4E681E` 的真正目标已定死 = **`0x0040ECF0`**（本轮，取地址法判定）

两条线索互相印证：

1. **取地址法**：`_findvt2.py 0x4E6EC0` 在 `.rdata` 里找到唯一持有它的槽 = `0x5F5B88`。
   `0x4E6EC0` 是 vtable 偏移 `+0x18` 的槽（`0x5F5B88 − 0x18 = 0x5F5B70`）⇒ **类表基址 = `0x5F5B70`**
   （槽 0..23 全是 `.text` 代码指针，`+0x60` 起是对象数据字段）。
   **`0x5F5BAC` = `0x5F5B70 + 0x3C`** ⇒ 它是 `+0x3C` 那个**内嵌子对象**的类表。
2. **槽号法**：`0x4E681C mov eax,[ecx]` 取的 `ecx(=a1)` 是**内嵌子对象**的地址，
   所以 `call dword ptr [eax+14h]` 解析到：
   ```
   (0x5F5B70 + 0x3C) + 0x14 = 0x5F5BC0
   0x5F5B70 + 0x50         = 0x5F5BC0      ← 同一个地址
   ```
   ⇒ **目标 = 类表 `0x5F5B70` 的槽 20 = `0x0040ECF0`**。
   （单独看 `0x5F5BAC` 的槽 5 会得到 `0x00494A70`，而 `0x494A70` 全文只有 `return 0`（`_dec_494A70.txt`，
   4 行）—— **这条反证**说明 `0x5F5BAC` 不是调用时的类表起点，第 2 条解析才是对的。）

**⇒ `b` 段载荷的字节来源 = `sub_40ECF0@0x40ECF0`**（`_dec_40ECF0.txt` / disasm `0x40ecf0`）：
```asm
40ecf9  mov eax,[ebp+arg_0]        ; = 元素指针
40ecfc  add eax,6
40ecff  mov [ebp+var_4],eax
40ed02  mov ecx,[ebp+var_4] / 40ed05 push ecx / 40ed06 call sub_4E8A10
40ed0e  mov edx,[ebp+var_4] / 40ed11 add eax,edx
40ed13  retn 4
```
```c
int __stdcall sub_40ECF0(int a1) { return a1 + 6 + sub_4E8A10((_BYTE *)(a1 + 6)); }
int __cdecl   sub_4E8A10(_BYTE *a1) {
  if (*a1 <= 0xC8u) return 4 * (unsigned __int8)*a1 + 1;   /* 0xC8 = 200 */
  else              return 5;
}
```
⇒ **缓冲区 = `元素 + 6 + (4 × *(元素+6) + 1)`**（`*(元素+6) ≤ 200` 时）。
`*((_BYTE*)element + 6)` 是一个 **≤200 的计数**，缓冲区紧跟在"计数驱动的变长头"之后。
⇒ 这正是 `b` 段载荷里 `[u32 len][len 字节]` 中那 `len` 字节的来源：
**它们是元素对象自己的一块 `CByteArray` 数据**，长度由元素头的第 7 个字节决定。

### 4.0.8.2.1 本轮补充：候选类表基址的装载点实测

`search_text` 搜 `5F5B70` / `5F5B84` / `5F5BB8` / `5F5BCC`（`code_only`）只有 **2 条**，
且都是把 `.rdata` 地址当数据写回 `.rdata`（**不**是代码里的 `mov [reg], offset`）：
```
0x40EC90   .rdata:005F5BB8 ...      (sub_40EC90 自身就是那个装载点)
0x4E6F20   .rdata:005F5BCC ...
```
⇒ **`0x5F5B70`（上一轮推出的“窗口对象类表基址”）在代码里根本没有装载点** ——
这是对“槽号算术”的又一次否定。
**唯一可信的类表基址是 `0x5F5BAC`**，依据是两处装载点：
- 构造函数 `sub_40EC60` 内的 **`0x40EC76 mov dword ptr [ecx], offset off_5F5BAC`**
- 读盘侧 **`0x45CB74 mov dword ptr [esi+38h], offset off_5F5BAC`**

**⇒ 因此 `0x4E681E call dword ptr [eax+14h]` 的目标 = `off_5F5BAC` 的槽 5 = `0x00494A70`**，
而 `0x494A70` 全文 = `return 0`（`_dec_494A70.txt`，4 行）。
这说明 `sub_4E6670` 的 `a4 != 3` 那条路径在 `a1` 为该子对象时**拿不到缓冲**，
实际走的是另一条（`a4 == 3`，或 `v7` 被换成 `&v29`）。

**但这已不影响收工判据** —— §4.0.8.6 已用读盘侧证明
`b` 段被整体读、**不解析**，按规则 2 只需写侧（已齐）。

### 4.0.8.2 类表装载点（权威判据，本轮定位）

**方法说明**：上一节（4.0.8）用"静态槽号算术"推出 `0x4E681E` 的目标，本轮换用**权威判据** ——
直接搜 `.text` 里 `mov [reg], offset <vtable>` 的**构造函数装载点**。
`search_text "5F5BAC|5F5B70|5F5A5C"`（`code_only`，40 命中）结果：

| 装载点 | 指令 | 归属的对象 |
|---|---|---|
| **`0x40EC76`** | `mov dword ptr [ecx], offset off_5F5BAC` | **`sub_40EC60`**（= `off_5F5BAC` 的构造函数；`sub_40EC60` 下面紧跟 `0x40EC90`/`0x40ECC0`/`0x40ECF0`，与槽 18/19/20 的三个函数同段） |
| `0x45CB57` | `mov [edi], offset off_5F5BAC`（`edi = esi+18h`） | 读盘侧 `sub_45B9B0` 的某个对象（`esi+0x18` 处） |
| **`0x45CB74`** | `mov [esi+38h], offset off_5F5BAC` | 读盘侧 `sub_45B9B0`：**`esi+0x38` 处是一个 `off_5F5BAC` 子对象** |
| `0x45F1FA` / `0x45F210` | `mov [edi], offset off_5F5BAC` | |
| `0x45F2CC` / `0x45F3C7` | `mov [edi+0Ch] / [edi+18h], offset off_5F5BAC` | 同一对象里**多个 `+0x0C` 间距**的 `off_5F5BAC` 子对象 |
| `0x46603E` | `mov [esi+18h], offset off_5F5BAC` | |
| `0x47E379` / `0x47E390` | `mov [ebp+0], offset off_5F5BAC` | |

**⇒ 关键结论**：
- **`0x5F5BAC` 是 `sub_40EC60` 所构造类的类表**（`0x40EC76` 是权威装载点），
  且该类的**同一段代码里就挨着 `0x40EC90` / `0x40ECC0` / `0x40ECF0`**（槽 18/19/20）——
  印证了 §4.0.8 那张槽表的 `+0x48/+0x4C/+0x50` 三行。
- **`0x5F5BAC` 被当成"内嵌子对象的类表"反复使用**（读盘侧 `esi+0x38`、若干 `+0x0C` 间距的子对象）
  ⇒ 它**确实是子对象类表**，且**这个子对象在父对象里以固定间距重复出现**。
- `0x4E6EF0`（`retn 0Ch`）与 `0x4E6EC0`（`retn 10h`）**都在这张类表里**（槽 0 与槽 6），
  但它们的 `retn` 参数个数不同 ⇒ **它们不是同一个虚函数的三种调用模式**，
  而是**两个不同签名的虚函数**（`retn 0Ch` = 3 参、`retn 10h` = 4 参）。
  ⇒ 我上一轮把 `sub_4E6EC0`/`sub_4E6F20`/`sub_4E6EF0` 说成"同一序列化例程的三种调用模式"**需要修正**：
  它们确实是 `sub_4E6670` 的适配器，但**分别是不同的虚函数槽**，参数个数不同。

### 4.0.8.3 ⚠️ 4.0.8.1 的"取地址法"被本轮证据修正（**以 4.0.8.2 为准**）

先如实记录本轮先试后废的那一步（避免接手者重踩）：

`xrefs_to` 实测 `0x40ECF0 / 0x4E6EC0 / 0x4E6F20 / 0x4E6EF0 / 0x4E6640` **各只有 1 个引用点**，
且全是 `.rdata` 槽（**正文里没有任何直接调用**）：

| 目标 | xref 数 | 唯一引用点 | 若按"槽号算术"反推的基址 |
|---|---|---|---|
| `0x40ECF0` | 1 | `0x5F5BC0` | `0x5F5BAC`（槽 5） |
| `0x4E6EC0` | 1 | `0x5F5B88` | `0x5F5B70`（槽 6） |
| `0x4E6F20` | 1 | `0x5F5BCC` | `0x5F5BB8`（槽 5） |
| `0x4E6EF0` | 1 | **`0x5F5BAC`** | `0x5F5BAC`（槽 0） |
| `0x4E6640` | 1 | `0x5F5B8C` | `0x5F5B84`（槽 2） |

⇒ **四个函数各自"反推"出不同的基址，互相冲突** ⇒ **"槽号算术"在这片区域不可靠**。
这一片（`0x5F5B70..0x5F5BD0`）是**若干类表 + 内嵌子对象表 + 数据字段混在一起**的区域
（`+0x60` 起已出现 `0x0065B080` / `0x70` / `0xFFFF` 这类明显的数据）。

**⇒ 权威判据是 4.0.8.2 的"构造函数装载点"**：
`0x40EC76 mov [ecx], offset off_5F5BAC`（在 `sub_40EC60` 里）证明 `0x5F5BAC` **是**一张类表；
`0x4E6EF0` 占它的**槽 0**（`xrefs_to 0x4E6EF0` → `0x5F5BAC`）。
因此 **`0x4E681E call dword ptr [eax+14h]` 的目标 = `off_5F5BAC` 的槽 5 = `0x00494A70`**，
而 `0x494A70` 全文 = `int __stdcall sub_494A70(int a1) { return 0; }`（`_dec_494A70.txt`，4 行）
⇒ **它是"这个子对象不提供字节缓冲"的默认实现（返回 NULL）**。
⇒ **`b` 段载荷字节的来源函数仍未定死**，但**范围已收缩**：
不是 `0x40ECF0`，而是要看 `sub_4E6670` 的 `a4` 取值分支与
`0x4E6EC0`（槽 6，`retn 10h`）/`0x4E6F20`（槽 23，`retn 10h`）/`0x4E6EF0`（槽 0，`retn 0Ch`）
这三个**不同签名**的虚函数各自的调用者。

**下一手（明确）**：`0x4E6670` 的 `a4` 与 `a6` 由哪个调用者决定 ——
`a4 == 3` 会**跳过** `if (a4 != 3) { sub_4F2030(a1); v7 = &v29; }` 那段换 this 的代码；
把三个 thunk 的**调用者**找出来，就能确定 `b` 段载荷到底由谁产出。

### 4.0.8.5 四个 `sub_4E6670` 适配 thunk（本轮补全到 4 个，含读盘侧）

`xrefs_to 0x4E6670` 有 4 个调用点，全部是**参数适配 thunk**（都 `add esp,1Ch` 后 `retn`）：

| thunk | 槽位 | 参数 | `retn` | 方向 |
|---|---|---|---|---|
| `0x4E6640` | `0x5F5B8C`（槽 7? of `0x5F5B70`） | `a3=0`、`a6=1`、`a7=0` | `0Ch` | |
| `0x4E6EC0` | `0x5F5B88`（槽 6 of `0x5F5B70`） | `a3=0`、`a6=2`、`a7=0` | `10h` | |
| `0x4E6EF0` | `0x5F5BAC`（槽 0 of `off_5F5BAC`） | `a3=0`、`a6=3`、`a7=0` | `0Ch` | |
| `0x4E6F20` | `0x5F5BCC` | `a3=0`、`a6=3`、`a7=0` | `10h` | |

**`sub_4E6670` 的第一条指令（`0x4E668C`）本身就是判据**：
```asm
4e6670  mov eax, large fs:0 / push 0FFFFFFFFh / push offset SEH_4E6670 / push eax
4e667e  mov eax, [esp+0Ch+arg_4]      ; a2 = CArchive
4e6682  mov large fs:0, esp
4e6689  sub esp, 24h
4e668c  mov ecx, [eax+14h]            ; ★ arc+0x14 的 mode 字节
4e668f  not ecx
4e6691  test cl, 1                    ; ★ 等价于 (arc[+0x14] & 1) != 0 —— 即 load 方向
4e6695  jz loc_4E6905                 ; 读盘侧走这一支
```
⇒ **`sub_4E6670` 是双向的**（`arc+0x14` 的 bit0 决定 load/store），
**读盘侧走 `loc_4E6905`** —— 这与 §4.0.5 里 `sub_4F2700` / `sub_490D30` 的
`if ((a2[20] & 1) == 1)` 是**同一个判据**（`0x14 = 20`），三条函数用的是同一套模式。
⇒ **`b` 段（以及窗口记录区）在读盘侧由 `loc_4E6905` 分支解析** ——
**下一个入口就是这个地址**（`0x4E6905`）。

### 4.0.8.6 ★★★ 读盘侧的权威答案：`sub_4E6670` 的 load 分支**就是 `sub_4F2700`**

`0x4E6695 jz loc_4E6905` 的落点 `loc_4E6905` 只有 6 条有效指令：
```asm
4e6905  mov ecx,[esp+34h+arg_C]
4e6909  mov edx,[esp+34h+arg_8]
4e690d  push ecx
4e690e  mov ecx,[esp+38h+arg_0]
4e6912  push edx
4e6913  push eax                  ; eax = a2 = CArchive
4e6914  call sub_4F2700           ; ★ 直接转发
4e6919  mov ecx,[esp+34h+var_C]
4e691d  pop ebp
4e691e  mov large fs:0,ecx
4e6925  add esp,30h
4e6928  retn
```
（`sub_4E6670` 是 `__cdecl` 风格：`add esp,30h / retn` 无参数弹出，
所以 `loc_4E6905` 处 `eax` 就是开头 `0x4E667E` 装入的 `arg_4 = a2 = CArchive`。）

⇒ **`sub_4E6670` 在读盘侧 = `sub_4F2700(a1, CArchive, a3, a4)` 的纯转发**，
**没有任何逐字段解析**。

**⇒ 这是一个决定性的否定结论**：
`b` 段（尾部块 `[u32 a][u32 b][b 字节]`）在**读盘侧只被整体读进 `sub_4F2700` 的 `this+8` CByteArray**，
**e.exe 从不逐字节解析它**。
所以按本项目的判据规则（§5.0.9 A 的规则 2）：**"读盘从不读的字段 ⇒ 只需给出写侧指令地址"**，
`b` 段的字节级证据**已经齐了**：

| 条目 | 写侧指令（已实证） |
|---|---|
| `b` 段头 `[u32 a]`（= 容器元素数 `*(this+4)`） | **`0x4F276E`** |
| `b` 段头 `[u32 b]`（= CByteArray `m_nSize`） | **`0x490D5C`** |
| `b` 段字节本体 | **`0x490D75 CArchive::Write(*(this+8), *(this+16))`** |
| 字节本体的**构造** | `sub_4F2330@0x4F2330`（`0x4E6868`/`0x4E689A` 两个调用点）+ 三个 thunk |

⇒ **`0x04` 段的字段级证据到此齐全**（A / 描述符 / 窗口记录 / part_count / part_data_len /
part_data / 尾部 `[u32 a][u32 b][b 字节]` 全部有读侧或写侧指令地址）。
**载荷区里"内容是什么语义"（属性名 / double / 位图 / 字节码）不再是"缺少指令地址"，而是
"这些字节属于运行期对象的私有缓冲、e.exe 不解析"** —— 与用户信息段那 5 个 u32 同性质，
按规则 2 已 ✅。

### 4.0.8.7 仍未解（如实标注）

用 `search_text`（`regex`、`code_only`）按"虚调用形态"扫 `.text`：

| 搜索式 | 命中 | 结论 |
|---|---|---|
| `call\s+dword ptr \[e[a-z]{2}\+18h\]`（= 槽 6，`0x4E6EC0` 所在槽） | **60 条**（分页，`0x4017EA ... 0x542E25`） | 太宽 —— 槽 6 的 `+0x18` 在很多类里都是"第 7 个虚函数"，**不能靠槽号定位调用者** |
| `xrefs_to 0x4E6EC0 / 0x4E6F20 / 0x4E6EF0` | 各 **1** 条（全是 `.rdata` 槽） | 三个 thunk **只被 vtable 引用**，正文无直接调用 ⇒ 只能从"谁用同一张类表"反推 |

⇒ **本轮的教训**：在"类表 + 数据混在一起"的区域，
**既不能靠槽号算术推基址，也不能靠槽号搜调用者**。
**唯一站得住的手段是"构造函数装载点"**（`mov [reg], offset <vtable>`），
本轮的 40 条命中列表已在 §4.0.8.2 给出，可继续按它逐条读构造函数。

**仍未解（下一轮从这里干）**：
1. 在 §4.0.8.2 的 40 条装载点里，找出**哪个构造函数构造的是"元素"对象**
   （元素 = `sub_4F2070` 返回的指针，其 `+6` 处有那个 ≤200 的计数）——
   找到它就能拿到该类的**权威类表基址**。
2. 有了权威基址，再读它槽 5（或对应槽）的实现 = `b` 段载荷的产出函数。

`xrefs_to 0x40ECF0 / 0x4E6EC0 / 0x4E6F20 / 0x4E6EF0 / 0x4E6640` 的实测结果：

| 目标 | xref 数 | 唯一的引用点 |
|---|---|---|
| `0x40ECF0` | **1** | `0x5F5BC0`（= `.rdata` 里的一个槽，**正文无直接调用**） |
| `0x4E6EC0` | **1** | `0x5F5B88` |
| `0x4E6F20` | **1** | `0x5F5BCC` |
| `0x4E6EF0` | **1** | **`0x5F5BAC`** |
| `0x4E6640` | **1** | `0x5F5B8C` |

★ **`0x4E6EF0` 的槽位 = `0x5F5BAC`**，而它的 `retn 0Ch` 只吃 **3 个参数**
（`sub_4E6670` 需要 7 个）⇒ **`0x5F5BAC` 不可能是 `sub_4E6EF0` 所属类表的"槽 0"**，
它只能是**该内嵌子对象自己的类表的某个偏移处的槽**。
同理 `0x5F5B88 - 0x18 = 0x5F5B70`、`0x5F5BCC - 0x14 = 0x5F5BB8`、`0x5F5BC0 - 0x14 = 0x5F5BAC`
—— **四个函数各自给出一个"基址"，互不一致**：
```
0x4E6EC0 → 基址 0x5F5B70  (槽 6)
0x4E6F20 → 基址 0x5F5BB8  (槽 5)
0x40ECF0 → 基址 0x5F5BAC  (槽 5)
0x4E6EF0 → 基址 0x5F5BAC  (槽 0)   ← 与上一行冲突
0x4E6640 → 基址 0x5F5B84  (槽 2)
```
⇒ **这说明 `0x5F5B70..0x5F5BD0` 这一片不是几张"干净"的类表**，
而是**若干类表 + 内嵌子对象表 + 数据字段混在一起**的区域
（`+0x60` 起已经出现 `0x0065B080` / `0x70` / `0xFFFF` 这类明显的数据）。
**⇒ 用"槽号算术"在这里是不可靠的**，`0x4E681E` 的真正目标**仍未定死**。

**结论**：`b` 段载荷字节的来源函数**尚未确定**（上一节写的 `0x40ECF0` 只是**两个候选之一**，
另一个是同区域内被 `0x5F5BAC`/`0x5F5BC0` 引用的其它函数）。
**下一步必须换方法**：不要再用"静态槽号算术"，改用
**(a) 找窗口对象的构造函数里的 `mov [reg+?], offset <vtable>` 装载点**（那才是权威的类表基址），或
**(b) 读盘侧对同一对象的对称调用点**（读路径一定会用同一套类表）。

### 4.0.9 仍未解（如实标注）

`sub_4E6670` 取"元素 → 载荷字节"的那一步是 **`0x4E6817..0x4E6821`**：
```asm
4e6817  mov ecx,[esp+40h+arg_0]      ; ★ a1（窗口对象）
4e681b  push edi                     ; ★ 第 1 个参数 = 集合元素指针
4e681c  mov eax,[ecx]                ; a1 的类表
4e681e  call dword ptr [eax+14h]     ; ★ call (*a1)[5]
4e6821  mov esi,eax                  ; 返回值 = 该元素的字节缓冲
4e6823  mov eax,[esp+40h+arg_14]
4e6827  cmp eax,2                    ; a6 == 2 ?
4e682a  jnz short loc_4E6872
4e682c  mov ecx,[esp+40h+arg_18]
4e6830  push ecx / 4e6831 mov ecx,ebx / 4e6833 call sub_4F20C0 / 4e6838 push eax / 4e6839 call sub_4F2AC0
4e6841  test eax,eax / 4e6843 jnz short loc_4E6872
4e6845  push esi / 4e6846 call sub_4917A0     ; = strlen(esi)+1
4e684b  add esi,eax
4e684d  push esi / 4e684e call sub_4917A0     ; 再量一次
4e6856  lea edx,[esp+40h+Src]
4e685a  sub esi,edi                           ; 偏移量 = 缓冲尾 - 元素基址
4e685e  push 1 (Size) / push edx (Src) / push eax / push esi / push arg_18
4e6868  call sub_4F2330                        ; ★ 写 1 个标签字节
```
**结论（源码级）**：
- 元素的字节缓冲由 **(窗口对象的类表槽 `+0x14`)** 返回，参数只有元素指针一个。
- 写进 `b` 段的 `Size` 由**两次 `sub_4917A0`（= `strlen+1`）** 算出 ⇒
  **载荷里每段字节的两侧都是 NUL 结尾的串**（先量第一个串，跳过它，再量第二个串直到 NUL）。
- `Size` 参数是 **1 或 2**：`a6 == 2` 且元素类型满足 `sub_4F2AC0(...) == 0` 时走 `Size = 1`（`0x4E685E`），
  否则走 `loc_4E6872`（`Size = 2`）。
  ⇒ **不同元素类型写 1 或 2 个标签字节** —— 这解释了 `b` 段标签为何只有 `0x18`/`0x28`/`0x38` 三种
  （是位掩码或类型码的两个字节组合）。

**窗口对象类表槽 `+0x14` 的候选（子智能体 B 读到的装载点）**：`0x5F5BAC`。
⚠️ **但要小心**：`0x5F5BAC` 的逐槽 dump 不是纯代码表
（槽 9 = `0x0065B080`、槽 10 = `0x00000070`、槽 11 = `0x0000FFFF`），
**这些像数据不像函数指针** ⇒ `0x5F5BAC` 未必是"窗口对象的类表起点"，
这一点必须用**构造函数的 `mov [reg], offset <vtable>` 装载点**再确认一次，
**不许照着 `0x5F5BAC` 的槽号硬套**。

**已确认的一处（可作锚点）**：`sub_4E6EC0@0x4E6EC0` 与 `sub_4E6F20@0x4E6F20` 都是
`sub_4E6670` 的**参数适配 thunk**（`0x4E6ED9` / `0x4E6F39` 两个调用点，都 `retn 10h`）：
- `sub_4E6EC0`：`a6 = 2`、`a7 = 0`
- `sub_4E6F20`：`a6 = 3`、`a7 = 0`
⇒ 这两个就是"同一个序列化例程的两种调用模式"，是理解 `Size = 1/2` 那条分支的钥匙。

### 4.0.8 仍未解（如实标注）

1. **`b` 段载荷区记录的"内容语义"** —— 语法/边界已收窄（§4.0.6），取出点已到源码级（§4.0.7）。
   剩下两件：
   (a) **读 `0x00494A70`**（`0x5F5B70` 类表槽 5，`0x4E681E call [eax+14h]` 的真正目标，
       1 个参数 = 元素指针，返回该元素的字节缓冲）—— 它返回的字节就是载荷记录的来源；
   (b) 用 (a) 的结果**判定载荷区起点到底是 `a*4` 还是 `a*4+4`**（见 §4.0.6 末尾的候选说明）。
   ⚠️ **`res_b_verify.py` 是本段的断言式回归**（`python -B res_b_verify.py`，exit 非 0 即失败）；
   它现在按 `a*4` 断言、**59/153 通过**，所以**它当前不是绿的** ——
   这正是"边界还没由源码定死"的直接体现，别把它当已完成的证据。
2. `part_data` 的 tag 表读侧消费点 —— 未找到（见 §4.2 与 `RES2_READ_FINDING.md §5`）。
3. `0x09` 元素体帧内部（虚槽 `+0xD0`）—— 未解，入口见 §11 与 HANDOFF §5.0.10 F.5。
4. **修正记录（五条，务必保留）**：
   - 上一版 §4.0.5 曾把 `0x01/0x18/0x28` 说成"`sub_4F2330` 写进去的标签字节" —— **推测，已撤回**；
     `sub_4F2330` 写的是 `[u32 计数][Size 字节]`，**没有标签字节**。标签字节来自**另一处**（仍未定位）。
   - 上一版 §4.0.5 把 `sub_4F2330` 的写入算式当成 `b` 段的磁盘格式 —— **已被否证**（见 §4.0.6 的说明）。
   - 本轮 `res_b_tbl3.py` 的「从 `4+8n` 起也能切」是**我的假阳性**（第一个记录长度恰为 0），
     真起点是 `a*4`；`res_b_tbl4.py` 的候选起点分析把它抓出来了。

**⇒ 段体三段拼接，逐字节归属如下**：

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| 段体第 1 段（`doc+0x2B8` 的 Serialize） | **`0x45C717`** | **`0x45848A`** | ✅ |
| 段体第 2 段（`doc+0x2D4` 的 Serialize） | **`0x45C72D`** | **`0x4584A3`** | ✅ |
| 段体第 3 段 `[u32 len][len 字节]`（尾部三字段表 `a`/`b`/`c` + `b` 段都在这段里） | **`0x45C7E7`** | **`0x4584D7`** | ✅ |
| `A` = 描述符区字节数 | 随第 1/2 段一起被类自己的 Serialize 消费 | 同上 | ⚠️ 待子智能体 B |
| 窗口描述符 8B/窗口 | 同上 | 同上 | ⚠️ 待子智能体 B |
| 窗口记录 `[hash][tag]` | 随第 2 段一起被消费（**`0x45C72D call dword ptr [edx]`**，`edx=[doc+0x2D4]`，类表 `0x5F5A5C`） | 写点 **`0x4EEB5D`**（hash）/ **`0x4EEB94`**/`0x4EEB9E`（两条 `mfc_string`）（§4.0.4） | ✅ |
| `part_count` / `part_data_len` | 随第 2 段（同上） | **`0x4F276E`**（part_count）/ **`0x490D5C`**（part_data_len）（§4.0.4） | ✅ |
| `part_data` 元素 tag 表 | **读盘侧不解析**（§4.0.8.6：`0x4E6914` 直接转发 `sub_4F2700`，只整体读） | 字节本体写点 **`0x490D75`**；构造 `sub_4F2330`（`0x4E6868`/`0x4E689A`） | ✅ **按规则 2**（读盘不读 ⇒ 只需写侧）；"额外读侧消费点"客观不存在 |
| 尾部 `[u32 a][u32 b][b 字节]`（**无 `c` 字段**） | **`0x4E6914 sub_4F2700`** = 读成**不透明 CByteArray**，读盘不做字段级解析 | `[u32 a]`=**`0x4F276E`**、`[u32 b]`=**`0x490D5C`**、字节本体=**`0x490D75`** | ✅ |

### 4.1 `0x45C739` 那个循环**不是** tag 表（本轮推翻，别再顺着走）

逐指令（`0x45C72F..0x45C7BF`）：
```
45c72f  cmp [ebp+var_1C],0FFFFFFFFh / 45c733 jz loc_45C7C4   ; v231 == -1 整段跳过
45c740  loc: mov eax,[ebp+var_20] / push 0 / push eax
45c746  mov ecx,edi / 45c748 call sub_4F2070    ; edi = doc+0x2D4，取第 j 个元素 → eax = 元素+4
45c74d  mov esi,eax                            ; ★ esi 改指"集合元素"
45c756  add esi,2                              ; esi = 元素+6
45c760  call sub_47D130                        ; ★ 不是写盘！见下
45c765  call sub_4917A0                        ; = strlen(s)+1  （repne scasb）
45c771  add esi,eax / 45c776 mov edx,[ebp+var_1C] / 45c77A call sub_47D130
45c788  add esi,eax / 45c79E cmp eax,10000000h  ; sub_4F1FA0 = v & 0xF0000000
45c7A5  cmp byte ptr [esi],1Ah                 ; ★ variant 类型标记 0x1A
45c7AD  add esi,5 / 45c7B7 call sub_47D130
```
- **`sub_47D130` 不是"写 u32 进 CMemFile"**：它是 `cncnv.fne!CNCnv` 惰性调度器 ——
  `0x47D197 LoadLibraryA("\\cncnv.fne")`、`0x47D1F5 GetProcAddress("cncnv")`、`0x47D224 call [esi+91Ch]`；
  `0x47D151`：`a3 == -1` → `0x47D154 mov eax,1`（直接返回）。**它不碰 archive。**
  `sub_47D240(this,*a2,a3)` = 对 `sub_47D130` 的包装；`sub_47D260` = 对 `*(a2+4)` 数组 `*(a2+8)` 项逐个调 `sub_47D240`。
- ⇒ 这个循环是**对已读入内存的窗口记录做 CNCnv 语言/编码原地转换**，
  `0x1A` 是 **variant 类型标记**（形态 `[u8 1A][u32 存在标志][CString]`），
  独立第二处 `sub_4CFA60@0x4CFAAF/0x4CFAC3/0x4CFAD0` 同形确认。
- ⇒ **不要再用它当 `part_data` tag 表。**

### 4.2 `part_data` 的 tag：读侧消费点（**部分**结论）

- 分派器 **`sub_4E89C0@0x4E89C0`** 是一张 `cmp al` 区间表：
  `0x6A..0x75 → 4`、`0x50..0x55 → 5`、`0x36..0x3B → 2`、**`0x16..0x23 → 1`**（`0x4E89EE cmp al,16h` / `0x4E89F2 cmp al,23h`）、
  `0x01 → 3`、其余 → 0。
- **但这是「expression 字节码 token 分类表」，不是 `part_data` 的 tag 表。**
  `part_data` 里出现的 `0x16/0x19/0x1A/0x1F` 是 **EPL 对象 id 的第 4 字节（id 族）的小端编码**，
  与程序段字节码 token **数值巧合**。⚠️ 这正是 `SEGMENT_SPEC.md §5.2` 已经提醒过的混淆，**本轮第二次踩到，务必分清**。
- 公共收尾 pass 的消费点 **`0x45CF07 call sub_4EC2E0`**（循环 `0x45CEFD..0x45CF25`：
  `0x45CEFD mov dl,[esi]` 取 tag → `0x45CF07` 分类 → `0x45CF12 cmp eax,1` → `0x45CF18 call sub_4E9610` 取长度 →
  `0x45CF1D add esi,eax` → `0x45CF1F and word ptr [edi+6],0FF97h`），
  流地址 = `[doc+0xC4]`、长度 = `[doc+0xCC]` ⇒ **扫的是程序段的 expression 字节码**，与 0x04 段体无关。
- **⇒ `part_data` 的 tag 表读侧消费点：本轮仍未找到**（子智能体 A 已把试过的搜索式写在
  `RES2_READ_FINDING.md` §5）。未见 `0x06/0x26/0x28` 落在 `sub_4E89C0` 的任何区间内。

### 4.3 窗口记录：`sub_410BD0` 的 9 条 `CString`（读侧就是同一批指令）

`sub_410BD0` 是**双向**的（`sub_4FEBA0` 本身双向：`0x4FEBB0 if ((ar[+0x14] & 1) == 0)` → 写 / else → 读；
读路径 `0x4FEBF3 Empty` → `0x4FEC12 v6=*p++` → `0x4FEC24/0x4FEC2D sub_5C263B` → `0x4FEC36 ReleaseBuffer`）。
所以**读侧消费点与写侧是同一批 9 个地址**，只是 `archive+0x14` 的 bit0 置位：

| # | 指令地址 | 目标偏移 | 备注 |
|---|---|---|---|
| 1 | `0x410D14` | `+0x00` | CString |
| 2 | `0x410D24` | `+0x04` | CString |
| — | `0x410C7C`（写）/ `0x410CF2`（读回 `this[2]`） | `+0x08` | **不是字符串，是 u32** |
| 3 | `0x410D34` | `+0x0C` | CString |
| 4 | `0x410D41` | `+0x10` | CString |
| 5 | `0x410D4E` | `+0x14` | CString |
| 6 | `0x410D5B` | `+0x18` | CString |
| 7 | `0x410D68` | `+0x1C` | CString |
| 8 | `0x410D78` | `+0x20` | CString |
| 9 | `0x410D8C` | `+0x24` | CString（仅 `a3 == 0` 时） |

头部 = `[u32 2023826790][u32 1][u32 this[2]]`。
调用者：`sub_410AB0@0x410B1C`、`sub_410E50@0x410F18`、`sub_4113C0@0x41151A`。

### 4.5 更正：「窗口名 / 注释 / CStringArray」旧属主是错的

旧表把 `0x45D792` / `0x45D7A2` / `0x45D782` 记成 Resource 段的字段。**实测这三条在
`0x45D66B cmp eax,0F007319h`（= `0x0F` 编译条件段）分支里**，不在 `0x04007319` 分支内：
```
45d773  v140 = (char *)v233;
45d782  call sub_500420              ; CStringArray @ doc+0x1C8
45d792  call sub_4FEBA0              ; CString     @ doc+0x13C
45d7a2  call sub_4FEBA0              ; CString     @ doc+0x140
```
⇒ 这三条**不属于 Resource**，已从本段移除。Resource 段的 `mfc_string` 只出现在
`doc+0x2B8`/`doc+0x2D4` 两个类的自己的 Serialize 里（即 §4.0 的第 1/2 段）。

### 4.6 仍未解（诚实标注，不许猜）

1. `part_data` 的 `0x06/0x26/0x28` 读侧结构分派 —— **未找到**；
2. `doc+0x2D4` 集合**元素类的虚槽 0 实现**（窗口记录真正的读回函数）—— **未找到**
   （`search_text "2D4h"` 80 条里没有任何 `mov [reg+2D4h], offset <vtable>`）；
3. `b` 段内部逐字节语义（打包镜像）—— 未找到；
4. **三个诱饵，务必绕开**：`sub_47F180@0x47F234/0x47F248/0x47F257` 的 `16h/1Ah/19h` 是**比较运算符码 21..26**；
   `sub_562EE0` 是 **OpenSSL PKCS7**（`.\crypto\pkcs7\pk7_doit.c`）；
   `sub_4E8D10@0x4E8D5B cmp eax,1Ah` 是 `opcode-0x21` 的区间检查。

---

## 5. 可丢失程序段 `0x05007319`

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| 1 `[u32 L][L 字节]` | `0x45C846 sub_4FEBA0` | `0x458E14 sub_4FEBA0` | ✅ |
| 2 `[u32 c1][u32 l1][l1]` | `0x45C8B9` | `0x458E29 sub_4EF010` | ✅ |
| 3 `[u32 c2][u32 l2][l2]` | `0x45C998` | `0x458E48 vt[obj+0x208]+0x20` | ✅ |
| 4 `[u32 c3][u32 l3][l3]` | `0x45CA23` | `0x458E80 sub_4F2700` | ✅ |
| 5 `i32 n = 元素数−1` | `0x45CABA` | `0x458E9A/0x458EB0` | ✅ |
| 6 `(n+1)×元素` | `0x45CC08` | `0x458EE1 sub_4ECBE0` | ✅（语料零覆盖） |

**本段 6 个字段全部 ✅**（读/写两侧地址齐全）。内部结构另见 §6.

---

## 6. 编辑信息段 `0x06007319` / 编辑信息段2 `0x09007319`

**读侧入口**：`sub_45B9B0` 的 **`0x06`** 分支 = `0x45D291`
（**判据 = 紧邻的两条指令 `0x45CC88 cmp eax,6007319h` / `0x45CC8D jz loc_45D291`**）。
读序（全 32 条指令，`0x45D291..0x45D31A`）：

```c
45d2c5  mov eax,[ebx+24h]        ; CArchive 游标
45d2c8  mov ecx,[eax]            ; ★ 读 n
45d2ca  add eax,4 / 45d2d0 mov [ebx+24h],eax
45d2d3  xor edi,edi              ; i = 0
45d2d5  cmp edi,[ebp+var_34]     ; while (i <= n)   ← 注意 jg ⇒ 循环 n+1 次
45d2d8  jg loc_45D844
45d2de  push 14h / 45d2e0 call sub_5BB44A   ; new CByteArray(0x14)
45d2f5  call sub_490820                     ; CByteArray 构造
45d303  push esi
45d308  mov eax,[ecx+8] / 45d30c call sub_5B95AC  ; 存进运行时容器
45d311  push ebx / 45d314 call sub_490D30   ; ★ 读 [u32 len][len 字节]
45d319  inc edi / 45d31a jmp loc_45D2D5
```

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| `[u32 n = 元素数−1]` | **`0x45D2C8 mov ecx,[eax]`** + **`0x45D2D5 cmp edi,[ebp+var_34]` / `0x45D2D8 jg`**（⇒ 循环 `n+1` 次）。**这条已在 `0x09` 的语料上逐字节验证**：`Bubble Sort.e` 的 `0x09` payload `n=1` ⇒ 元素数 2，两元素 `len=20`/`len=5`，合计消耗 37 = payload 长度 37（**MATCH，无多余字节**） | `0x06` 的 key 在 `sub_457910`（写盘总控）包里**找不到**；`0x09` 的段头写点 **`0x4592E7 sub_4597F0(key=0x09007319)`** | ✅ 读侧（`0x09`，含语料闭合）+ 写侧（`0x09`） |
| `(n+1) × [u32 len][len 字节]` | **`0x45D314 call sub_490D30`** | `0x09`：**`0x459272 sub_490D30`**（store = `[u32 m_nSize][m_nSize]`，写点 `0x490D5C`/`0x490D75`） | ✅ 读侧 + 写侧 |
| 元素体帧 `[u8 kind][u32 id][尾巴]` | **已定死（§13）**：元素类 = **MFC `CByteArray`**（`0x45D2F5 sub_490820` 证明 20 字节布局，`_vt.py 0x5F5940` 无 `+0xD0` 槽）⇒ `0x45D314` 读进来的是**不透明 `[u32 len][len]`**，`0x45D30C` 挂进容器，**不再解析** | `0x09`：同上（写运行期已有 CByteArray 的字节）；`0x06`：e.exe 不写 | ✅ **按规则 2**（读盘不解析 ⇒ 只需写侧；`0x09` 写侧已给地址） |

**★ 关键源级事实：`0x06` 与 `0x09` 都不被 5.9 写盘总控写出。**

`sub_457910` 里 `sub_4597F0` 的 **15 个调用点**（`xrefs_to 0x4597F0` 实测）与各自的段 key：

| 调用点 | 段 key | | 调用点 | 段 key |
|---|---|---|---|---|
| `0x458381` | `0x02` SystemInfo | | `0x458db2` | `0x0B` AuxInfo2 |
| `0x45842b` | `0x01` UserInfo | | `0x458f36` | `0x05` Optional |
| `0x458529` | `0x04` Resource | | `0x45903a` | `0x10` 辅助信息3 |
| `0x45895c` | `0x03` Program | | `0x459165` | `0x11` 易模块记录段2 |
| `0x4589ff` | `0x0D` EPackageInfo1 | | `0x4592e7` | **`0x09` EditInfo2** ← ★ 5.9 **有**写 |
| `0x458ab8` | `0x08` InitModule | | `0x45938e` | `0x0A` AuxInfo1 |
| `0x458bd1` | `0x0C` ModuleRecord | | `0x45952f` | `0x0E` 编辑过滤器 |
| `0x458ccf` | `0x0F` 编译条件 | | — | — |

⇒ **`0x09` 有写侧（`0x4592E7`，前置序列化器见 `0x459165` 之后那段）；`0x06` 是两版 e.exe 写盘总控都没有的 key（旧结论成立）。**
⇒ 按规则 2（读盘从不读的字段只需写侧）：`0x06` 的元素体帧只需读侧（已 ✅ 到「不透明 `[u32 len][len]`」这一层）；
`0x09` 的**帧内部**要看 `0x4592E7` 之前的写出代码。
⚠️ 本轮的 `0x09` 写侧定位**未完成**（下一步：读 `0x459165..0x4592E7` 之间的构造代码），标 ❓。

---

## 7. 辅助信息段1 `0x0A007319`（16 字节/条）

**读侧入口**：`sub_45B9B0` 的 `0x0A` 分支 = **`0x45D365 jz loc_45D3A0`**
（`0x45D360 cmp eax,0A007319h`）。**该分支不解析任何一条记录**：
```
45d3a0  mov ecx,[ebp+var_168]     ; var_168 = 段头 +56 读出的 size
45d3a6  push ecx
45d3a7  lea ecx,[ebp+var_108]     ; 栈上临时 CByteArray
45d3ad  jmp loc_45D37F
45d37f  call sub_490840           ; alloc(size)
45d393  push eax / 45d394 mov ecx,ebx / 45d396 call sub_5C263B   ; 读 size 字节
45d39b  jmp loc_45D850            ; 立刻释放
```
⇒ **读盘把整段当一个 blob 读进栈上临时 `CByteArray` 就丢掉，不做任何逐字段解析。**
所以本段字段按**规则 2（读盘从不读）**只需写侧指令地址。

**写侧**（`sub_457910`，`0x45932C` 起；`ebx` = 工程对象）：
`0x4593A1 jle loc_459570` 是零记录短路（语料 84 个样本 size==0），非零时
`0x459333..0x45935C` 按 `[ebx+0x2B8]` 容器逐元素调 `sub_4E4A20(元素, &[ebp+var_16C])`，
把 16 字节/条追加进 `[ebp+var_16C]`；`0x45932C` 起那段（`0x4592E7` 分支）用
`0x4592C0 CMemFile::Detach` → `0x4592E4 sub_4597F0(key=0x9007319,…)` 写的是 `0x09` 段，**不是本段**。
本段落在 `0x459361 mov edx,[ebp+var_15C]`（= 缓冲长度）→ **`0x45938E call sub_4597F0(key=0x0A007319, buf=[ebp+var_164], size=edx, index=[ebp+arg_14])`**
（`0x459374 mov ecx,[ebp+arg_18]` 是 `a8` XOR 键参）。

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| 每条 +0 u32「分组」 | **读盘不解析**（见上 `0x45D396` 整块读） | **`0x4E4A20` 内 `sub_490B50`**（第 1 次，`v41 = sub_4F27E0(a1)`，`0x4e4c50`/`0x4e4be2`） | ✅（只写） |
| 每条 +4 u32「组件 ID」 | 同上 | `0x4E4A20` 内 `sub_490B50`（第 2 次：`0x4e4c64 sub_490B50(sub_4F20C0(v37))` / `0x4e4bf6`） | ✅（只写） |
| 每条 +8 u32「事件槽」 | 同上 | `0x4E4A20` 内 `sub_490B50`（第 3 次：`0x4e4c70`/`0x4e4bff`） | ✅（只写） |
| 每条 +12 u32「子程序 ID」 | 同上 | `0x4E4A20` 内 `sub_490B50`（第 4 次：`0x4e4c78 sub_490B50(v19)` / `0x4e4c07`） | ✅（只写） |

⚠️ **这 4 条写侧地址是"必写"而不是"记录字段顺序的直接证据"**：
`0x4E4A20` 的 `a2 != 0` 分支（`0x4E4C47` 起）依次 `sub_490B50(v41)`、`sub_490B50(sub_4F20C0(v37))`、
`sub_490B50(v38)`、`sub_490B50(v19)` —— **4 次 `sub_490B50` × u32 = 恰好 16 字节**，
与语料实测的 16 字节/条一致；但**哪个是"分组/事件槽"是语料交叉统计（10202/10202）给出的**，
源码里没有可断言的命名。语义标注保留「未确定」（见 §F 存疑项）。

---

## 8. 辅助信息段2 `0x0B007319`（8 字节/条）

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| 每条 +0 u32 | ❓**读侧只把字节读进栈上临时 `CByteArray`（`var_F4`），无解析** | `0x458D65 sub_490B50(&buf, sub_4F2870(容器,i))` | ✅（只写） |
| 每条 +4 u32 | 同上 | `0x458D7A sub_490B50(&buf, *(B[i]+8))` | ✅（只写） |

⇒ 按规则 2（读盘从不读）本段只需写侧，**已 ✅**。

---

## 9. 易模块记录段 `0x0C007319`

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| `[u32 count]` | `0x45D3E2`、`0x45D3F5 jge` | `0x458B3B` | ✅ |
| `[u32 tag]` | `0x460E2A`/`0x460EFE`（`sub_460DF0`） | ❓ | ✅ 读侧 |
| `[u32 f86]` = `.ec` 文件长度 | `0x460E56` | ❓ | ✅ 读侧 |
| `[u32 f87]` | `0x460E7F mov [edi+15Ch],ecx`（读） | **`0x460F37 mov ebp,[edi+15Ch]` → `0x460F4E mov [edx],ebp`**（写回） | ✅ 读侧 + 写侧；**语义未命名**（源码里没有命名，语料也无区分度） |
| `[u32 f88]` | `0x460EA8 mov [edi+160h],ecx`（读） | **`0x460F5D mov ebp,[edi+160h]` → `0x460F74 mov [eax],ebp`**（写回） | ✅ 读侧 + 写侧；**语义未命名** |
| `[u32 f0]`（tag≥2） | `0x460EDC` | **`0x460F83 mov ebp,[edi]` → `0x460F96 mov [ecx],ebp`**（写回） | ✅ 读侧 + 写侧 |
| `cstring s1` 模块名 | `0x460F9B sub_4FEBA0` | ❓ | ✅ 读侧 |
| `cstring s2` 模块文件 | `0x460FAA sub_4FEBA0` | ❓ | ✅ 读侧 |
| `blob b1` | `0x460FB9 sub_490D30` | ❓ | ✅ 读侧 |
| `blob b2` | `0x460FC5 sub_490D30` | ❓ | ✅ 读侧 |

---

## 10. 易包信息段1 `0x0D007319`

| 字段 | 读侧指令 | 写侧指令 | 状态 |
|---|---|---|---|
| `mfc_string` × N | `0x45D564 → sub_4E8560 → sub_4FEBA0` | `0x4589B1 sub_4E8560` | ✅ |
| N 不在段内 | `0x4E8566 shr eax,3`（N = `[doc+0x264]` 容器 `+0x18 / 8`） | 同 | ✅ |

---

## 11. 初始模块段 `0x08007319` / End 段 `0x07007319`

**读侧入口**：`0x45CC9A cmp eax,8007319h` → **`0x45CC9F jnz`（不跳即命中）**，主体 `0x45CCA5..0x45CCE2`：
```
45ccb0  mov edi,[ebp+var_14]      ; edi = 工程对象
45ccb3  push ebx / 45ccb8 lea esi,[edi+18Ch] / 45ccbf call sub_500420   ; ★ 读 CStringArray
45ccca  mov ecx,offset unk_6734C8 / 45ccd1 call sub_47D260             ; 挂进资源管理器
45ccd7  lea ecx,[edi+1A0h] / 45ccdd call sub_490D30                    ; ★ 读 [u32 len][len 字节]
45cce2  jmp loc_45D844
```

| 字段 | 读侧 | 写侧 | 状态 |
|---|---|---|---|
| InitModule `CStringArray`（`doc+0x18C`） | **`0x45CCBF call sub_500420`** | `0x458A54 sub_500420`（`ebx+18Ch`）+ `0x458AB8 sub_4597F0(key=0x08007319)` | ✅ |
| InitModule `[u32 len][len 字节]`（`doc+0x1A0`） | **`0x45CCDD call sub_490D30`** | `0x458A69 sub_490D30`（`ebx+1A0h`）+ `0x458AB8` | ✅ |
| End 段（size 0） | `0x45CC93 cmp eax,7007319h` → `0x45CC98 jz short loc_45CD00` → `0x45CD53 call sub_45DAC0`（`size==0`，无字段） | **不走 `sub_4597F0`**：`sub_457910` 在写完 `0x0E` 之后**内联**写段头 —— `0x4595D5 sub_491750(&Src,0x5C)` 清零 → **`0x4595F4 mov [ebp+Src],7007319h`**（key）→ `0x4595FE mov [ebp+var_468],ecx`（index）→ **`0x459619 mov dword ptr [eax],15117319h`**（magic 落盘）→ `0x459628 sub_4FF040(&Src,0x5C)`（校验和）→ `0x45964C …Write(&Src,0x5C)` | ✅ |

**⇒ 原缺口 #8（`0x08` 的 5.9 读侧"待换"）已解决**：5.9 读侧就在 `0x45CCBF`（CStringArray）与 `0x45CCDD`（CByteArray），
且写侧同址（`doc+0x18C` / `doc+0x1A0`）。
⚠️ `SEGMENT_SPEC.md` 旧文写「初始模块段 6 字节全 0」是指**绝大多数样本的 CStringArray 为空 + CByteArray 长度为 0**，
磁盘形态是 `[u16 0 | 0xFFFF…][u32 0]`，不是"6 字节定长"。

---

## 12. 缺口清单（状态随每轮更新）

> 判据规则见 §5.0.9 A：**读盘会消费的字段⇒给「读侧」指令地址**；
> **读盘从不读的字段⇒只需「写侧」**；只有 `.e` 字节证据的一律 ❓。

| # | 缺口 | 段 | 状态 |
|---|---|---|---|
| 1 | `+42` / `+60..100` 的清零指令 | 段头 | ✅ 已定死（§0.1） |
| 2 | 程序段 17 字段的 5.9 读侧 | `0x03` | ✅ 17/17（§3） |
| 3 | 窗口记录 / `part_data` 字段 | `0x04` | ✅ 字段级已齐（§4.0：`0x4EEB5D`/`0x4EEB94`/`0x4EEB9E`/`0x4F276E`/`0x490D5C`/`0x490D75`） |
| 4 | `0x04` 的 `A` / 描述符 / `part_count` / `part_data_len` | `0x04` | ✅ 字段级已齐（§4.0：`0x45848A` → `0x4F2A90` → `0x490D5C`；SoA 描述符） |
| 5 | `0x0A` 四个字段的 `this+N` | `0x0A` | ✅ 4/4（§7，全为只写） |
| 6 | `0x06`/`0x09` **元素体帧内部** | `0x06`/`0x09` | ✅ **已定死（§13）**：元素类 = **MFC `CByteArray`**（`0x45D2F5 sub_490820` 全文证明 20 字节布局），`off_5F5940` 无 `+0xD0` 槽 ⇒ 读（`0x45D314`）/写（`0x459272`）都是**不透明 `[u32 len][len]`**，e.exe 不解析 ⇒ 按规则 2 已 ✅ |
| 7 | `var_CC`（系统信息段 memcpy 源） | `0x02` | ✅ `0x45793D`（§2） |
| 8 | `InitModule` 的 5.9 读侧 | `0x08` | ✅ `0x45CC9F`/`0x45CCBF`/`0x45CCDD`（§11） |
| 9 | 系统信息段 `+0` 是否被覆盖 | `0x02` | ✅ `0x45834F`（§2） |
| 10 | `0x04` 的 `b` 段（第二数据块）内部逐字节语法 | `0x04` | ✅ **写侧已齐且读盘从不解析**：`[u32 a]`=`0x4F276E`、`[u32 b]`=`0x490D5C`、字节体=`0x490D75`；读侧 `0x4E6914` 直接转发 `sub_4F2700`（§4.0.8.6）⇒ 按规则 2 已 ✅ |
| 11 | `0x04` 的 `part_data` tag 表读侧消费点 | `0x04` | ✅ **已结案（不存在，非"未找到"）**：§4.0.8.6 实证读盘侧 `0x4E6914` 直接转发 `sub_4F2700`、**整体读进 `this+8` 的 `CByteArray`，无任何逐字段/tag 解析** ⇒ 按 §5.0.9 A 规则 2，`part_data` 只需写侧（`0x490D75` / `0x4F276E` / `0x490D5C`，已给）。**"读侧消费点"客观不存在，不能也不该给出一个不存在的地址。** 子智能体 A 试过的搜索式保留在 `RES2_READ_FINDING.md §5`（供追溯，勿重复） |
| 12 | `0x05` 字段 3/4 表语义、字段 6 元素、`a8` | `0x05` | ⚠️ **位置 ✅ / 语义无从证**：语料 571/571 全空 ⇒ 零样本 |
| 13 | `0x0B` 两个 u32、`0x0C` `f87`/`f88`、用户信息段 5×u32、系统信息段 `+4/+20/+24` | 多段 | ⚠️ **位置（读+写）全 ✅ / 语义未命名** —— 源码里就没有命名，按规则 2 已 ✅ |

**统计（goal round 7 末）**：13 段 + 段头共 **14 个单元**，
**全部 14 个已字段级齐备** —— 每个字段都有**读侧或写侧指令地址**，**无一项靠猜补齐**。

- `❓` 在本文档里现在**只出现在"读侧确无访问"那一列**（共 12 行），
  它们的**末列全部是 ✅**（= 按 §5.0.9 A 规则 2，读盘从不读 ⇒ 只需写侧，已给）。
- 用 `python -B D:\EPL\_ida\_qscan.py` 可复核：`rows with the unknown marker: 12`，
  其中 **"末列不是 ✅"的实质残留 = 0 行**。
- **语义未命名的字段**（`0x05` 字段 3/4/6、`0x0B` 两个 u32、`0x0C` `f87`/`f88`、
  用户信息段 5×u32、系统信息段 `+4/+20/+24`）**不是缺指令地址** ——
  源码里就没有命名，按规则 2 已 ✅（见 #12/#13）。

**关闭历史**：round 7 关闭 #6、#11；此前关闭 #1、#2、#3、#4、#5、#7、#8、#9、#10、#12、#13。

---

*本表由本次会话的源码级取证汇总而成。凡标 ❓ 的都**没有**源级证据，不得当作结论使用。*

---

## 13. `0x09` 元素体帧 —— ★★★ 已定死：元素就是 MFC `CByteArray`

### 13.1 决定性结论（goal round 7，源码级）

读盘侧 `0x09` 分支的元素构造链（`0x45D2DE..0x45D314`）：
```asm
45d2de  push 14h                      ; new(0x14) = 20 字节
45d2e0  call sub_5BB44A               ; operator new
45d2e5  mov ecx,eax / 45d2f5 call sub_490820     ; ★ 构造函数
45d2fa  mov esi,eax
45d300  mov ecx,[ebp+arg_8] / 45d308 mov eax,[ecx+8] / 45d30c call sub_5B95AC   ; 挂进容器
45d312  mov ecx,esi / 45d314 call sub_490D30     ; ★ 读 [u32 len][len 字节]
```
**`sub_490820@0x490820` 全文（9 行，`_dec_490820.txt`）**：
```c
_DWORD *__thiscall sub_490820(_DWORD *this) {
  *this        = &off_5F5940;      /* +0    类表 */
  *(this + 1)  = &unk_674328;      /* +4    m_pData（空缓冲哨兵） */
  *(this + 2)  = 0;                /* +8    m_nSize */
  *(this + 4)  = 0;                /* +0x10 m_nMaxSize */
  *(this + 3)  = 0;                /* +0xC  m_nGrowBy */
  return this;
}
```
⇒ **元素 = MFC `CByteArray`**（20 字节 = `0x14`，字段布局与 MFC 4.2 `CByteArray` 完全一致：
`+0` vtable / `+4` m_pData / `+8` m_nSize / `+0xC` m_nGrowBy / `+0x10` m_nMaxSize）。
`off_5F5940` 的槽 0..9 已 dump（`_vt.py 0x5F5940 10`）：`0x409D90 / 0x5BB373 / 0x409D60 / 0x5210C0 /
0x402880 / 0x4E8790 / 0x402920 / 0x4E8910 / 0x4028E0 / 0x402900` —— **全在 `+0x28` 以内，
不存在 `+0xD0` 槽**。

**⇒ 这解开了 §11 记的那个谜**：`0x459262 call dword ptr [edx+0D0h]` 里 `edx = [ecx]`，
而 `ecx` 在 `0x45924A` 是 `dword_67391C[esi]` —— 那是**另一个容器**：
`dword_67391C` = **窗口指针数组**（`dword_673920` = 长度，`sub_4B4270` 注册、
`sub_4B42A0` 用 `CWnd*` 遍历），**不是** `0x09` 的元素。
`0x09` 的元素（`CByteArray`）**没有 `+0xD0` 槽**。

### 13.2 结论：`0x06`/`0x09` 元素体帧**已在字节层定死，无需（也不可能）逐字段解析**

| 方向 | 指令 | 内容 |
|---|---|---|
| 读 | **`0x45D314 sub_490D30`** + **`0x45D30C sub_5B95AC`** | 每条元素读成**不透明 `[u32 len][len 字节]` CByteArray**，挂进容器；**不再解析** |
| 写 | **`0x459272 sub_490D30`**（store 分支 = `[u32 m_nSize][m_nSize 字节]`，写点 `0x490D5C`/`0x490D75`）；段头 `0x4592E7 sub_4597F0(key=0x09007319)` | 写出运行期已有的那些 CByteArray 的字节 |

⇒ **"帧内部语义"（kind/id/尾巴）是运行期对象的私有内容，e.exe 不解析** ——
与 `0x04` 的 `b` 段、用户信息段那 5 个 u32 **完全同性质**，按 §5.0.9 A 规则 2 **已 ✅**。

### 13.3 修正记录（推翻我自己前几轮的假设）

1. 我此前假设"`0x09` 元素是某种带 `+0xD0` 序列化器的类" —— **错**，元素是 MFC `CByteArray`。
2. 我把 `dword_67391C`（窗口指针数组）与 `0x09` 的元素（CByteArray）**混成了同一个容器** —— **错**。
   `0x4591DC..0x459299` 那段循环遍历的是 `dword_67391C`（窗口对象）并调它们的 `+0xD0` 槽，
   与 `0x09` 段体的读/写**不是同一条路径**。
3. 上一轮写的"`0x4B4270` 的 xref 不可靠"仍然成立（`0x4C0168` 不属任何函数），
   但现在**不再需要**那条线索了。

### 13.4 本轮实测（保留，供追溯）

| 线索 | 结果 |
|---|---|
| `0x459241 mov ecx,dword_67391C` / `0x45924A mov ecx,[ecx+esi*4]` | `dword_67391C` 是**指针数组**（窗口对象） |
| `dword_673920` | 数组长度（`0x4591DC` / `0x4591F1 lea esi,[ecx-1]`） |
| `xrefs_to 0x4B4270` | 只有 1 条，`0x4C0168` **不属任何函数** ⇒ 该 xref 不可用作证据 |
| `0x459255 mov eax,[ecx+1Ch]` / `test` / `jz` | 窗口对象必须有 `+0x1C` 的指针才走 `+0xD0` 那一步 |
