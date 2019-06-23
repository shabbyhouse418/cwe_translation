## <center>CWE翻译计划</center>
<p align="right">-- by UESTC 418</p>
**贡献人员：**<br>
&ensp;*Mardan & Szg(shang Cr7-joker) & LJIJCJ & Michael Tan*



## <font color=gray>**CWE - 5	J2EE Misconfiguration: Data Transmission Without Encryption**</font><br>
中文：**J2EE配置错误：没有加密的数据传输**<br>
- ### Description
&ensp;通过网络发送的信息在传输过程中可能会受到影响。如果数据以明文发送或者是弱加密，则攻击者可能能够读取或修改内容。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 6	J2EE Misconfiguration: Insufficient Session-ID Length**</font><br>
中文：**J2EE配置错误：会话ID长度不足**<br>
- ### Description
&ensp;J2EE应用程序配置为使用不足的会话ID长度。
- ### Extended Description
&ensp;如果攻击者可以猜测或窃取会话ID，那么他们就可以接管用户的会话（称为会话劫持）。可能的会话ID的数量随着会话ID长度的增加而增加，使得猜测或窃取会话ID变得更加困难。<br>

## <font color=gray>**CWE - 7	J2EE Misconfiguration: Missing Custom Error Page**</font><br>
中文：**J2EE配置错误：缺少自定义错误页面**<br>
- ### Description
&ensp;Web应用程序的默认错误页面不应显示有关软件系统的敏感信息。
- ### Extended Description
&ensp;Web应用程序必须为4xx错误（例如404），5xx（例如500）错误定义默认错误页面并捕获java.lang.Throwable异常以防止攻击者从应用程序容器的内置错误响应中挖掘信息。
当攻击者探索寻找漏洞的网站时，该网站提供的信息量对于任何企图攻击的最终成功或失败至关重要。<br>

## <font color=gray>**CWE - 8	J2EE Misconfiguration: Entity Bean Declared Remote**</font><br>
中文：**J2EE配置错误：实体Bean声明为远程**<br>
- ### Description
&ensp;当应用程序公开实体bean的远程接口时，它还可能公开获取或设置bean数据的方法。可以利用这些方法来读取敏感信息，或以违反应用程序期望的方式更改数据，从而可能导致其他漏洞。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 9	J2EE Misconfiguration: Weak Access Permissions for EJB Methods**</font><br>
中文：**J2EE配置错误：EJB方法的弱访问权限**<br>
- ### Description
&ensp;如果将提升的访问权限分配给EJB方法，则攻击者可以利用这些权限来利用软件系统。
- ### Extended Description
&ensp;如果EJB部署描述符包含一个或多个授予对特殊ANYONE角色的访问权限的方法权限，则表示尚未完全考虑应用程序的访问控制，或者应用程序的结构是以合理的访问控制限制为不可能。<br>

## <font color=gray>**CWE - 11	ASP.NET Misconfiguration: Creating Debug Binary**</font><br>
中文：**ASP.NET配置错误：创建调试二进制文件**<br>
- ### Description
&ensp;调试消息可帮助攻击者了解系统并规划一种攻击形式。
- ### Extended Description
&ensp;可以将ASP .NET应用程序配置为生成调试二进制文件。这些二进制文件提供详细的调试消息，不应在生产环境中使用。调试二进制文件旨在用于开发或测试环境，如果将它们部署到生产环境中，则可能会带来安全风险。<br>

## <font color=gray>**CWE - 12	ASP.NET Misconfiguration: Missing Custom Error Page**</font><br>
中文：**ASP.NET配置错误：缺少自定义错误页面**<br>
- ### Description
&ensp;ASP .NET应用程序必须启用自定义错误页面，以防止攻击者从框架的内置响应中挖掘信息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 13	ASP.NET Misconfiguration: Password in Configuration File**</font><br>
中文：**ASP.NET配置错误：配置文件中的密码**<br>
- ### Description
&ensp;在配置文件中存储明文密码允许任何能够读取文件的人访问受密码保护的资源，使其成为攻击者的轻松目标。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 14	Compiler Removal of Code to Clear Buffers**</font><br>
中文：**编译器删除代码以清除缓冲区**<br>
- ### Description
&ensp;根据源代码清除敏感内存，但编译器优化会在不再次读取内存时保持内存不变，即“死存储删除”。
- ### Extended Description
&ensp;发生以下编译器优化错误：

1.秘密数据存储在内存中。
2.通过覆盖其内容从内存中清除秘密数据。
3.使用优化编译器编译源代码，该编译器识别并删除将内容覆盖为死存储的函数，因为随后不使用该存储器。<br>

## <font color=gray>**CWE - 15	External Control of System or Configuration Setting**</font><br>
中文：**系统外部控制或配置设置**<br>
- ### Description
&ensp;一个或多个系统设置或配置元素可以由用户外部控制。
- ### Extended Description
&ensp;允许外部控制系统设置可能会中断服务或导致应用程序以意外和潜在的恶意方式运行。<br>

## <font color=gray>**CWE - 20	Improper Input Validation**</font><br>
中文：**输入验证不正确**<br>
- ### Description
&ensp;产品不验证或错误验证可能影响程序的控制流或数据流的输入。
- ### Extended Description
&ensp;当软件未正确验证输入时，攻击者能够以应用程序其余部分不期望的形式制作输入。这将导致系统的某些部分接收到非预期的输入，这可能导致控制流的改变，资源的任意控制或任意代码执行。<br>

## <font color=gray>**CWE - 22	Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**</font><br>
中文：**限制目录的路径名的不正确限制（“路径遍历”）**<br>
- ### Description
&ensp;该软件使用外部输入来构造路径名，该路径名用于标识位于受限父目录下的文件或目录，但该软件未正确中和路径名中可能导致路径名解析到的位置的特殊元素在受限制的目录之外。
- ### Extended Description
&ensp;许多文件操作都是在受限目录中进行的。通过使用诸如“..”和“/”分隔符之类的特殊元素，攻击者可以在受限制的位置之外逃逸，以访问系统中其他位置的文件或目录。最常见的特殊元素之一是“../”序列，在大多数现代操作系统中，它被解释为当前位置的父目录。这被称为相对路径遍历。路径遍历还包括使用绝对路径名，例如“/ usr / local / bin”，这在访问意外文件时也很有用。这被称为绝对路径遍历。
在许多编程语言中，注入空字节（0或NUL）可能允许攻击者截断生成的文件名以扩大攻击范围。例如，软件可以将“.txt”添加到任何路径名，从而将攻击者限制为文本文件，但空注入可以有效地消除此限制。<br>

## <font color=gray>**CWE - 23	Relative Path Traversal**</font><br>
中文：**相对路径遍历**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的序列，例如“..”。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。<br>

## <font color=gray>**CWE - 24	Path Traversal: '../filedir'**</font><br>
中文：**路径遍历：'../filedir'**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的“../”序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
“../”操作是对使用“/”作为目录分隔符的操作系统的规范操作，例如基于UNIX和Linux的系统。在某些情况下，在支持“/”但不支持主分隔符的环境中绕过保护方案很有用，例如Windows，它使用“\”但也可以接受“/”。<br>

## <font color=gray>**CWE - 25	Path Traversal: '/../filedir'**</font><br>
中文：**路径遍历：'/../filedir'**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的“/../”序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
有时程序会在输入开头检查“../”，因此“/../”可以绕过该检查。<br>

## <font color=gray>**CWE - 26	Path Traversal: '/dir/../filename'**</font><br>
中文：**路径遍历：'/ dir /../filename'**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的“/dir/../filename”序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'/dir/../filename'操作对于绕过某些路径遍历保护方案很有用。有时程序只在输入开头检查“../”，因此“/../”可以绕过该检查。<br>

## <font color=gray>**CWE - 27	Path Traversal: 'dir/../../filename'**</font><br>
中文：**路径遍历：'dir /../../ filename'**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的多个内部“../”序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'目录/../../ filename'操作对于绕过某些路径遍历保护方案很有用。有时程序只删除一个“../”序列，因此多个“../”可以绕过该检查。或者，此操作可用于绕过路径名开头的“../”检查，向上移动多个目录级别。<br>

## <font color=gray>**CWE - 28	Path Traversal: '..\filedir'**</font><br>
中文：**路径遍历：'.. \ filedir'**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的“..”序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'.. \'操作是对使用“\”作为目录分隔符（如Windows）的操作系统的规范操作。但是，它也可用于绕过仅假设“/”分隔符有效的路径遍历保护方案。<br>

## <font color=gray>**CWE - 29	Path Traversal: '\..\filename'**</font><br>
中文：**路径遍历：'\ .. \ filename'**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的'\ .. \ filename'（前导反斜点点）序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
这类似于CWE-25，除了使用“\”而不是“/”。有时程序会在输入的开头检查“.. \”，因此“\ .. \”可以绕过该检查。它也可用于绕过仅假设“/”分隔符有效的路径遍历保护方案。<br>

## <font color=gray>**CWE - 30	Path Traversal: '\dir\..\filename'**</font><br>
中文：**路径遍历：'\ dir \ .. \ filename'**<br>
- ### Description
&ensp;该软件使用外部输入来构造一个应该在受限目录内的路径名，但是它没有正确地中和'\ dir \ .. \ filename'（前导反斜点点）序列，这些序列可以解析到该区域之外的位置目录。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
这类似于CWE-26，除了使用“\”而不是“/”。 '\ dir \ .. \ filename'操作对于绕过某些路径遍历保护方案很有用。有时程序只在输入的开头检查“.. \”，因此“\ .. \”可以绕过该检查。<br>

## <font color=gray>**CWE - 31	Path Traversal: 'dir\..\..\filename'**</font><br>
中文：**路径遍历：'dir \ .. \ .. \ filename'**<br>
- ### Description
&ensp;该软件使用外部输入来构造一个应该在受限目录内的路径名，但是它没有正确地中和'dir \ .. \ .. \ filename'（多个内部反斜杠点点）序列，这些序列可以解析为一个位置。在该目录之外。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'dir \ .. \ .. \ filename'操作对于绕过某些路径遍历保护方案很有用。有时程序只删除一个“..”序列，因此多个“.. \”可以绕过该检查。或者，此操作可用于绕过路径名开头的“.. \”检查，向上移动多个目录级别。<br>

## <font color=gray>**CWE - 32	Path Traversal: '...' (Triple Dot)**</font><br>
中文：**路径遍历：'...'（三点）**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的“...”（三点）序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
“...”操作对于绕过某些路径遍历保护方案很有用。在某些Windows系统上，它等同于“.. \ ..”并可能绕过假设只有两个点有效的检查。不完整的过滤，例如去除“./”序列，最终会产生有效的“..”序列，因为它们会陷入不安全的值（CWE-182）。<br>

## <font color=gray>**CWE - 33	Path Traversal: '....' (Multiple Dot)**</font><br>
中文：**路径遍历：'....'（多点）**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和可以解析到该目录之外的位置的“......”（多点）序列。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'....'操作对于绕过某些路径遍历保护方案很有用。在某些Windows系统上，它相当于“.. \ .. \ ..”并可能绕过假设只有两个点有效的检查。不完整的过滤，例如去除“./”序列，最终会产生有效的“..”序列，因为它们会陷入不安全的值（CWE-182）。<br>

## <font color=gray>**CWE - 34	Path Traversal: '....//'**</font><br>
中文：**路径遍历：'.... //'**<br>
- ### Description
&ensp;该软件使用外部输入来构造一个应该在受限目录内的路径名，但是它没有正确地中和可以解析到该目录之外的位置的“.... //”（加倍点点斜杠）序列。 。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'.... //'操作对于绕过某些路径遍历保护方案很有用。如果“../”按顺序方式过滤，如某些正则表达式引擎所做，则“.... //”可以折叠为“../”不安全值（CWE-182）。如果操作系统将“//”和“/”视为等效，则删除“..”时也可能有用。<br>

## <font color=gray>**CWE - 35	Path Traversal: '.../...//'**</font><br>
中文：**路径遍历：'... / ... //'**<br>
- ### Description
&ensp;该软件使用外部输入来构造一个应该在受限目录内的路径名，但是它没有正确地中和可以解析到外部位置的'... / ... //'（加倍的三点斜杠）序列那个目录。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。
'... / ... //'操作对于绕过某些路径遍历保护方案很有用。如果“../”按顺序方式过滤，如某些正则表达式引擎所做，则“... / ... //”可以折叠为“../”不安全值（CWE-182）。删除第一个“../”会产生“.... //”;第二次删除产生“../”。根据算法，软件可能对CWE-34敏感，但对CWE-35不敏感，反之亦然。<br>

## <font color=gray>**CWE - 36	Absolute Path Traversal**</font><br>
中文：**绝对路径遍历**<br>
- ### Description
&ensp;该软件使用外部输入来构造应该在受限目录内的路径名，但它不能正确地中和绝对路径序列，例如“/ abs / path”，它可以解析到该目录之外的位置。
- ### Extended Description
&ensp;这允许攻击者遍历文件系统以访问受限目录之外的文件或目录。<br>

## <font color=gray>**CWE - 37	Path Traversal: '/absolute/pathname/here'**</font><br>
中文：**路径遍历：'/ absolute / pathname / here'**<br>
- ### Description
&ensp;在没有适当验证的情况下以斜杠绝对路径（'/ absolute / pathname / here'）的形式接受输入的软件系统可以允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 38	Path Traversal: '\absolute\pathname\here'**</font><br>
中文：**路径遍历：'\ absolute \ pathname \ here'**<br>
- ### Description
&ensp;在没有经过适当验证的情况下以反斜杠绝对路径（'\ absolute \ pathname \ here'）的形式接受输入的软件系统可以允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 39	Path Traversal: 'C:dirname'**</font><br>
中文：**路径遍历：'C：dirname'**<br>
- ### Description
&ensp;攻击者可以将驱动器号或Windows卷号（“C：dirname”）注入软件系统，以潜在地重定向对非预期位置或任意文件的访问。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 40	Path Traversal: '\\UNC\share\name\' (Windows UNC Share)**</font><br>
中文：**路径遍历：'\\ UNC \ share \ name \'（Windows UNC Share）**<br>
- ### Description
&ensp;攻击者可以将Windows UNC共享（'\\ UNC \ share \ name'）注入软件系统，以潜在地重定向对非预期位置或任意文件的访问。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 41	Improper Resolution of Path Equivalence**</font><br>
中文：**路径等价的不正确解决方案**<br>
- ### Description
&ensp;系统或应用程序容易受到路径等效的文件系统内容泄露。路径等效涉及在文件和目录名称中使用特殊字符。相关的操作旨在为同一对象生成多个名称。
- ### Extended Description
&ensp;通常采用路径等价来规避使用不完整的文件名或文件路径表示表示的访问控制。这与路径遍历不同，其中执行操作以生成不同对象的名称。<br>

## <font color=gray>**CWE - 42	Path Equivalence: 'filename.' (Trailing Dot)**</font><br>
中文：**路径等价：'文件名。' （尾随点）**<br>
- ### Description
&ensp;在没有适当验证的情况下接受尾随点（'filedir。'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 43	Path Equivalence: 'filename....' (Multiple Trailing Dot)**</font><br>
中文：**路径等价：'filename ....'（多个尾随点）**<br>
- ### Description
&ensp;在没有适当验证的情况下接受多个尾随点（'filedir ....'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 44	Path Equivalence: 'file.name' (Internal Dot)**</font><br>
中文：**路径等价：'file.name'（内部点）**<br>
- ### Description
&ensp;在没有适当验证的情况下接受内部点（'file.ordir'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 45	Path Equivalence: 'file...name' (Multiple Internal Dot)**</font><br>
中文：**路径等价：'文件...名称'（多个内部点）**<br>
- ### Description
&ensp;在没有适当验证的情况下接受多个内部点（'file ... dir'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 46	Path Equivalence: 'filename ' (Trailing Space)**</font><br>
中文：**路径等价：'文件名'（尾随空格）**<br>
- ### Description
&ensp;在没有适当验证的情况下接受尾随空间（'filedir'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 47	Path Equivalence: ' filename' (Leading Space)**</font><br>
中文：**路径等价：'文件名'（前导空格）**<br>
- ### Description
&ensp;在没有适当验证的情况下接受前导空间（'filedir'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 48	Path Equivalence: 'file name' (Internal Whitespace)**</font><br>
中文：**路径等价：'文件名'（内部空白）**<br>
- ### Description
&ensp;在没有经过适当验证的情况下接受内部空间（'文件（SPACE）名称'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 49	Path Equivalence: 'filename/' (Trailing Slash)**</font><br>
中文：**路径等价：'filename /'（尾随斜线）**<br>
- ### Description
&ensp;在没有适当验证的情况下以尾部斜杠（'filedir /'）的形式接受路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 50	Path Equivalence: '//multiple/leading/slash'**</font><br>
中文：**路径等价：'// multiple / leading / slash'**<br>
- ### Description
&ensp;在没有适当验证的情况下以多个前导斜杠（'// multiple / leading / slash'）的形式接受路径输入的软件系统可能导致模糊的路径解析并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 51	Path Equivalence: '/multiple//internal/slash'**</font><br>
中文：**路径等价：'/ multiple // internal / slash'**<br>
- ### Description
&ensp;在没有适当验证的情况下以多个内部斜杠（'/ multiple // internal / slash /'）的形式接受路径输入的软件系统可能导致模糊路径解析并允许攻击者将文件系统遍历到非预期的位置或任意访问文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 52	Path Equivalence: '/multiple/trailing/slash//'**</font><br>
中文：**路径等价：'/ multiple / trailing / slash //'**<br>
- ### Description
&ensp;在没有适当验证的情况下以多个尾部斜杠（'/ multiple / trailing / slash //'）的形式接受路径输入的软件系统可能导致模糊的路径解析并允许攻击者将文件系统遍历到非预期的位置或任意访问文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 53	Path Equivalence: '\multiple\\internal\backslash'**</font><br>
中文：**路径等价：'\ multiple \\ internal \ backslash'**<br>
- ### Description
&ensp;在没有经过适当验证的情况下以多个内部反斜杠（'\ multiple \ trailing \\ slash'）的形式接受路径输入的软件系统可能导致模糊的路径解析并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 54	Path Equivalence: 'filedir\' (Trailing Backslash)**</font><br>
中文：**路径等价：'filedir'（尾随反斜杠）**<br>
- ### Description
&ensp;在没有适当验证的情况下以尾随反斜杠（'filedir \'）的形式接受路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 55	Path Equivalence: '/./' (Single Dot Directory)**</font><br>
中文：**路径等价：'/。/'（单点目录）**<br>
- ### Description
&ensp;在没有经过适当验证的情况下接受单点目录漏洞（'/./'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 56	Path Equivalence: 'filedir*' (Wildcard)**</font><br>
中文：**路径等价：'filedir *'（通配符）**<br>
- ### Description
&ensp;在没有经过适当验证的情况下接受星号通配符（'filedir *'）形式的路径输入的软件系统可能导致模糊的路径解析，并允许攻击者将文件系统遍历到非预期的位置或访问任意文件。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 57	Path Equivalence: 'fakedir/../realdir/filename'**</font><br>
中文：**路径等价：'fakedir /../ realdir / filename'**<br>
- ### Description
&ensp;该软件包含限制对“realdir / filename”的访问的保护机制，但它使用“fakedir /../ realdir / filename”形式的外部输入构造路径名，这些输入不由这些机制处理。这允许攻击者对目标文件执行未经授权的操作。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 58	Path Equivalence: Windows 8.3 Filename**</font><br>
中文：**路径等效：Windows 8.3文件名**<br>
- ### Description
&ensp;该软件包含一个保护机制，限制在Windows操作系统上访问长文件名，但该软件没有正确限制对等效的短“8.3”文件名的访问。
- ### Extended Description
&ensp;在以后的Windows操作系统中，文件可以具有“长名称”和与旧Windows文件系统兼容的短名称，文件名最多8个字符，扩展名最多3个字符。因此，这些“8.3”文件名充当具有长名称的文件的备用名称，因此它们是有用的路径名等效操作。<br>

## <font color=gray>**CWE - 59	Improper Link Resolution Before File Access ('Link Following')**</font><br>
中文：**文件访问前的链接解析不正确（'链接跟随'）**<br>
- ### Description
&ensp;软件会尝试根据文件名访问文件，但不能正确阻止该文件名识别解析为非预期资源的链接或快捷方式。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 61	UNIX Symbolic Link (Symlink) Following**</font><br>
中文：**UNIX符号链接（符号链接）以下**<br>
- ### Description
&ensp;打开文件或目录时，该软件无法充分说明文件是何时解析为目标控制范围之外的目标的符号链接。这可能允许攻击者使软件对未经授权的文件进行操作。
- ### Extended Description
&ensp;允许UNIX符号链接（符号链接）作为路径的一部分的软件系统，无论是在内部代码中还是通过用户输入，都允许攻击者欺骗符号链接并将文件系统遍历到非预期的位置或访问任意文件。符号链接可以允许攻击者读取/写入/损坏他们最初没有访问权限的文件。<br>

## <font color=gray>**CWE - 62	UNIX Hard Link**</font><br>
中文：**UNIX硬链接**<br>
- ### Description
&ensp;当打开文件或目录时，该软件不足以说明名称何时与目标控制范围之外的目标的硬链接相关联。这可能允许攻击者使软件对未经授权的文件进行操作。
- ### Extended Description
&ensp;系统检查硬链接失败可能导致不同类型的攻击。例如，如果特权程序使用的文件被替换为敏感文件的硬链接（例如/ etc / passwd），则攻击者可以升级其权限。当进程打开文件时，攻击者可以承担该进程的权限。<br>

## <font color=gray>**CWE - 64	Windows Shortcut Following (.LNK)**</font><br>
中文：**Windows快捷方式（.LNK）**<br>
- ### Description
&ensp;打开文件或目录时，如果文件是目标位于预期控制范围之外的Windows快捷方式（.LNK），则该软件无法充分处理。这可能允许攻击者使软件对未经授权的文件进行操作。
- ### Extended Description
&ensp;快捷方式（扩展名为.lnk的文件）可以允许攻击者读取/写入他们最初没有访问权限的文件。<br>

## <font color=gray>**CWE - 65	Windows Hard Link**</font><br>
中文：**Windows硬链接**<br>
- ### Description
&ensp;当打开文件或目录时，该软件在名称与目标控制范围之外的目标的硬链接相关联时无法充分处理。这可能允许攻击者使软件对未经授权的文件进行操作。
- ### Extended Description
&ensp;系统检查硬链接失败可能导致不同类型的攻击。例如，如果特权程序使用的文件被替换为敏感文件的硬链接（例如AUTOEXEC.BAT），则攻击者可以升级其权限。当进程打开文件时，攻击者可以承担该进程的权限，或阻止程序准确处理数据。<br>

## <font color=gray>**CWE - 66	Improper Handling of File Names that Identify Virtual Resources**</font><br>
中文：**识别虚拟资源的文件名处理不当**<br>
- ### Description
&ensp;产品不处理或错误处理标识“虚拟”资源的文件名，该文件名未在与文件名关联的目录中直接指定，导致产品对非资源上的资源执行基于文件的操作文件。
- ### Extended Description
&ensp;虚拟文件名称表示为普通文件名，但它们实际上是其他资源的别名，这些资源的行为与普通文件不同。根据其功能，它们可以是备用实体。它们不一定列在目录中。<br>

## <font color=gray>**CWE - 67	Improper Handling of Windows Device Names**</font><br>
中文：**Windows设备名称处理不当**<br>
- ### Description
&ensp;该软件从用户输入构造路径名，但它不处理或错误地处理包含Windows设备名称（如AUX或CON）的路径名。当应用程序尝试将路径名作为常规文件处理时，这通常会导致拒绝服务或信息泄露。
- ### Extended Description
&ensp;未正确处理虚拟文件名（例如AUX，CON，PRN，COM1，LPT1）可能导致不同类型的漏洞。在某些情况下，攻击者可以通过在URL中注入虚拟文件名来请求设备，这可能导致导致拒绝服务的错误或显示敏感信息的错误页面。允许设备名称绕过过滤的软件系统会冒着攻击者在具有设备名称的文件中注入恶意代码的风险。<br>

## <font color=gray>**CWE - 69	Improper Handling of Windows ::DATA Alternate Data Stream**</font><br>
中文：**Windows :: DATA备用数据流处理不当**<br>
- ### Description
&ensp;该软件无法正确阻止对备用数据流（ADS）的访问或检测其使用。
- ### Extended Description
&ensp;攻击者可以使用ADS从系统或文件浏览器工具（如Windows资源管理器）和命令行实用程序中的“dir”隐藏有关文件的信息（例如，大小，进程名称）。或者，攻击者可能能够绕过关联数据分叉的预期访问限制。<br>

## <font color=gray>**CWE - 71	DEPRECATED: Apple '.DS_Store'**</font><br>
中文：**弃用：Apple'.DS_Store'**<br>
- ### Description
&ensp;此条目已被弃用，因为它表示UNIX Hard Link弱点类型的特定观察示例，而不是其自身的个别弱点类型。请参阅CWE-62。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 72	Improper Handling of Apple HFS+ Alternate Data Stream Path**</font><br>
中文：**Apple HFS +备用数据流路径处理不当**<br>
- ### Description
&ensp;该软件无法正确处理可能识别HFS +文件系统上文件的数据或资源分支的特殊路径。
- ### Extended Description
&ensp;如果软件根据文件名选择要采取的操作，则如果攻击者提供数据或资源分支，则软件可能会采取意外操作。此外，如果软件打算限制对文件的访问，则攻击者仍可能通过请求该文件的数据或资源分支来绕过预期的访问限制。<br>

## <font color=gray>**CWE - 73	External Control of File Name or Path**</font><br>
中文：**文件名或路径的外部控制**<br>
- ### Description
&ensp;该软件允许用户输入来控制或影响文件系统操作中使用的路径或文件名。
- ### Extended Description
&ensp;这可能允许攻击者访问或修改对应用程序至关重要的系统文件或其他文件。
满足以下两个条件时会发生路径操作错误：

1.攻击者可以指定文件系统上的操作中使用的路径。
2.通过指定资源，攻击者获得了不允许的功能。

例如，程序可能使攻击者能够覆盖指定的文件或使用受攻击者控制的配置运行。<br>

## <font color=gray>**CWE - 74	Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')**</font><br>
中文：**下游组件使用的输出中特殊元素的中和不当（'注入'）**<br>
- ### Description
&ensp;该软件使用来自上游组件的外部影响输入构造命令，数据结构或记录的全部或部分，但它不会中和或不正确地中和可能修改它被发送到下游组件。
- ### Extended Description
&ensp;软件对数据和控制的构成分别有一定的假设。缺乏对用户控制输入的这些假设的验证导致注入问题。注射问题包含各种各样的问题 - 所有问题都以非常不同的方式得到缓解，并且通常是为了改变过程的控制流程。因此，讨论这些弱点的最有效方法是注意将它们归类为注入弱点的独特特征。需要注意的最重要的问题是所有注入问题都有一个共同点 - 即，它们允许将控制平面数据注入用户控制的数据平面。这意味着可以通过合法数据通道发送代码来改变进程的执行，而不使用其他机制。虽然缓冲区溢出和许多其他缺陷涉及使用一些进一步的问题来获得执行，但注入问题仅需要解析数据。这类弱点的最经典的实例是SQL注入和格式字符串漏洞。<br>

## <font color=gray>**CWE - 75	Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)**</font><br>
中文：**未将特殊元素消毒到不同的平面（特殊元素注入）**<br>
- ### Description
&ensp;对于具有控制意义的特殊元素，该软件不能充分过滤用户控制的输入。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 76	Improper Neutralization of Equivalent Special Elements**</font><br>
中文：**等效特殊元素的中和不当**<br>
- ### Description
&ensp;该软件适当地中和了某些特殊元素，但它不正确地中和了等效的特殊元素。
- ### Extended Description
&ensp;该软件可能具有其认为完整的特殊字符的固定列表。但是，可能存在具有相同含义的替代编码或表示。例如，软件可以过滤掉前导斜杠（/）以防止绝对路径名称，但不会考虑后跟用户名的波浪号（〜），在某些* nix系统上可以将其扩展为绝对路径名。或者，软件可能在调用外部程序时过滤危险的“-e”命令行开关，但它可能不会考虑“--exec”或具有相同语义的其他开关。<br>

## <font color=gray>**CWE - 77	Improper Neutralization of Special Elements used in a Command ('Command Injection')**</font><br>
中文：**命令中使用的特殊元素的不正确中和（'命令注入'）**<br>
- ### Description
&ensp;该软件使用来自上游组件的外部影响输入构造全部或部分命令，但它不会中和或不正确地中和可能在将命令发送到下游组件时修改预期命令的特殊元素。
- ### Extended Description
&ensp;命令注入漏洞通常在以下情况下发生：

1.数据从不受信任的来源进入应用程序。
2.数据是应用程序作为命令执行的字符串的一部分。
3.通过执行该命令，应用程序为攻击者提供了攻击者不具备的特权或能力。

命令注入是包装器程序的常见问题。<br>

## <font color=gray>**CWE - 78	Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')**</font><br>
中文：**OS命令中使用的特殊元素的中和不正确（'OS命令注入'）**<br>
- ### Description
&ensp;该软件使用来自上游组件的外部影响输入构造全部或部分OS命令，但它不会中和或不正确地中和可能在将其发送到下游组件时修改预期OS命令的特殊元素。
- ### Extended Description
&ensp;这可能允许攻击者直接在操作系统上执行意外的危险命令。这种弱点可能导致攻击者无法直接访问操作系统的环境中存在漏洞，例如在Web应用程序中。或者，如果弱点发生在特权程序中，则可能允许攻击者指定通常无法访问的命令，或者使用攻击者没有的特权来调用备用命令。如果受损的进程不遵循最小权限原则，则问题会更加严重，因为攻击者控制的命令可能会以特殊的系统权限运行，从而增加损害的数量。
OS命令注入至少有两种子类型：


该应用程序打算执行一个由其自己控制的单个固定程序。它打算使用外部提供的输入作为该程序的参数。例如，程序可能使用系统（“nslookup [HOSTNAME]”）来运行nslookup并允许用户提供HOSTNAME，该HOSTNAME用作参数。攻击者无法阻止nslookup执行。但是，如果程序没有从HOSTNAME参数中删除命令分隔符，则攻击者可以将分隔符放入参数中，这允许它们在nslookup完成执行后执行自己的程序。
应用程序接受一个输入，用于完全选择要运行的程序以及要使用的命令。应用程序只是将整个命令重定向到操作系统。例如，程序可能使用“exec（[COMMAND]）”来执行用户提供的[COMMAND]。如果COMMAND受攻击者控制，则攻击者可以执行任意命令或程序。如果使用exec（）和CreateProcess（）等函数执行命令，则攻击者可能无法在同一行中将多个命令组合在一起。


从弱点的角度来看，这些变体代表了不同的程序员错误。在第一个变体中，程序员明确地希望来自不可信方的输入将成为要执行的命令中的参数的一部分。在第二个变体中，程序员不打算让任何不受信任的方可以访问该命令，但程序员可能没有考虑恶意攻击者可以提供输入的替代方式。<br>

## <font color=gray>**CWE - 79	Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**</font><br>
中文：**网页生成期间输入的中和不正确（“跨站点脚本”）**<br>
- ### Description
&ensp;在将用户可控输入放入用作提供给其他用户的网页的输出之前，该软件不会中和或不正确地中和用户可控输入。
- ### Extended Description
&ensp;跨站点脚本（XSS）漏洞发生在：

1.不受信任的数据通常来自Web请求进入Web应用程序。
2. Web应用程序动态生成包含此不受信任数据的网页。
3.在页面生成期间，应用程序不会阻止数据包含Web浏览器可执行的内容，例如JavaScript，HTML标记，HTML属性，鼠标事件，Flash，ActiveX等。
4.受害者通过Web浏览器访问生成的Web页面，该Web浏览器包含使用不受信任的数据注入的恶意脚本。
5.由于脚本来自Web服务器发送的网页，因此受害者的Web浏览器会在Web服务器的域中执行恶意脚本。
6.这实际上违反了Web浏览器的同源策略的意图，该策略指出一个域中的脚本不应该能够访问资源或在不同的域中运行代码。

XSS有三种主要类型：


类型1：反射的XSS（或非持久性） - 
         服务器直接从HTTP请求读取数据并将其反映在HTTP响应中。当攻击者导致受害者向易受攻击的Web应用程序提供危险内容时，会发生反射的XSS攻击，然后将其反射回受害者并由Web浏览器执行。传递恶意内容的最常见机制是将其作为参数包含在公开发布或直接通过电子邮件发送给受害者的URL中。以这种方式构建的URL构成了许多网络钓鱼方案的核心，攻击者诱使受害者访问引用易受攻击网站的URL。在站点将攻击者的内容反映回受害者之后，内容由受害者的浏览器执行。

类型2：存储的XSS（或持久） - 
               应用程序将危险数据存储在数据库，消息论坛，访问者日志或其他可信数据存储中。稍后，危险数据随后被读回应用程序并包含在动态内容中。从攻击者的角度来看，注入恶意内容的最佳位置是在向许多用户或特别有趣的用户显示的区域中。有趣的用户通常在应用程序中具有提升的权限，或者与对攻击者有价值的敏感数据进行交互。如果这些用户之一执行恶意内容，则攻击者可能能够代表用户执行特权操作或访问属于该用户的敏感数据。例如，攻击者可能会将XSS注入日志消息，当管理员查看日志时，可能无法正确处理。
            

类型0：基于DOM的XSS  - 
               在基于DOM的XSS中，客户端执行将XSS注入页面;在其他类型中，服务器执行注入。基于DOM的XSS通常涉及发送到客户端的服务器控制的可信脚本，例如在用户提交表单之前对表单执行完整性检查的Javascript。如果服务器提供的脚本处理用户提供的数据，然后将其注入网页（例如使用动态HTML），则可以使用基于DOM的XSS。
            

一旦注入恶意脚本，攻击者就可以执行各种恶意活动。攻击者可以将受害者机器上的私人信息（例如可能包含会话信息的cookie）传输给攻击者。攻击者可以代表受害者向网站发送恶意请求，如果受害者具有管理该网站的管理员权限，则可能对该网站特别危险。网络钓鱼攻击可用于模拟受信任的网站，并欺骗受害者输入密码，允许攻击者破坏受害者在该网站上的帐户。最后，该脚本可以利用Web浏览器本身的漏洞，可能接管受害者的计算机，有时也称为“偷袭黑客”。
在许多情况下，攻击可以在受害者甚至没有意识到的情况下发起。即使有细心的用户，攻击者也经常使用各种方法来编码攻击的恶意部分，例如URL编码或Unicode，因此请求看起来不那么可疑。<br>

## <font color=gray>**CWE - 80	Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)**</font><br>
中文：**网页中与脚本相关的HTML标记的中和不当（基本XSS）**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和特殊字符，例如“<”，“>”和“＆”，当它们被发送到下游组件时可被解释为Web脚本元素处理网页。
- ### Extended Description
&ensp;这可以允许将这些字符视为控制字符，其在用户会话的上下文中在客户端执行。虽然这可以归类为注入问题，但更相关的问题是在将这些特殊字符显示给用户之前将这些特殊字符不正确地转换到相应的上下文相关实体。<br>

## <font color=gray>**CWE - 81	Improper Neutralization of Script in an Error Message Web Page**</font><br>
中文：**错误消息网页中脚本的中和不正确**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和可能在发送到错误页面时被解释为Web脚本元素的特殊字符。
- ### Extended Description
&ensp;错误页面可能包括自定义的403 Forbidden或404 Not Found页面。
当攻击者可以触发包含未中和输入的错误时，可能会发生跨站点脚本攻击。<br>

## <font color=gray>**CWE - 82	Improper Neutralization of Script in Attributes of IMG Tags in a Web Page**</font><br>
中文：**网页中IMG标记属性中脚本的中和不当**<br>
- ### Description
&ensp;Web应用程序不会中和或错误地中和HTML IMG标记属性中的脚本元素，例如src属性。
- ### Extended Description
&ensp;攻击者可以将XSS攻击嵌入到流式传输然后在受害者浏览器中执行的IMG属性（例如SRC）的值中。请注意，当页面加载到用户的浏览器中时，漏洞会自动执行。<br>

## <font color=gray>**CWE - 83	Improper Neutralization of Script in Attributes in a Web Page**</font><br>
中文：**网页属性中脚本的中和不正确**<br>
- ### Description
&ensp;该软件不会中和或错误地中和“javascript：”或来自标签内危险属性的其他URI，例如onmouseover，onload，onerror或style。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 84	Improper Neutralization of Encoded URI Schemes in a Web Page**</font><br>
中文：**网页中编码URI方案的中和不正确**<br>
- ### Description
&ensp;Web应用程序不正确地中和了用URI编码伪装的可执行脚本的用户控制输入。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 85	Doubled Character XSS Manipulations**</font><br>
中文：**双字符XSS操作**<br>
- ### Description
&ensp;Web应用程序不会过滤用户控制的输入，因为可执行脚本使用相关字符加倍来伪装。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 86	Improper Neutralization of Invalid Characters in Identifiers in Web Pages**</font><br>
中文：**网页中标识符中无效字符的中和不正确**<br>
- ### Description
&ensp;该软件不会中和或错误地中和标记名称，URI方案和其他标识符中间的无效字符或字节序列。
- ### Extended Description
&ensp;某些Web浏览器可能会删除这些序列，从而导致输出可能具有意外的控制含义。例如，软件可能会尝试删除“javascript：”URI方案，但“java％00script：”URI可能会绕过此检查，并且仍会被某些浏览器呈现为活动javascript，从而允许XSS或其他攻击。<br>

## <font color=gray>**CWE - 87	Improper Neutralization of Alternate XSS Syntax**</font><br>
中文：**备用XSS语法的中和不正确**<br>
- ### Description
&ensp;该软件不会中和或错误地中和用户控制的输入以获得备用脚本语法。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 88	Argument Injection or Modification**</font><br>
中文：**参数注入或修改**<br>
- ### Description
&ensp;该软件没有充分划分传递给另一个控件领域中的组件的参数，允许提供备用参数，从而导致潜在的安全相关更改。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 89	Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')**</font><br>
中文：**SQL命令中使用的特殊元素的中和不正确（'SQL注入'）**<br>
- ### Description
&ensp;该软件使用来自上游组件的外部影响输入构造全部或部分SQL命令，但它不会中和或不正确地中和可能在发送到下游组件时修改预期SQL命令的特殊元素。
- ### Extended Description
&ensp;如果没有在用户可控输入中充分删除或引用SQL语法，则生成的SQL查询可以将这些输入解释为SQL而不是普通用户数据。这可用于更改查询逻辑以绕过安全检查，或插入修改后端数据库的其他语句，可能包括执行系统命令。
SQL注入已经成为数据库驱动的网站的常见问题。该漏洞很容易被检测到，并且容易被利用，因此，任何具有最小用户群的站点或软件包都可能遭受此类攻击。这个缺陷取决于SQL在控制平面和数据平面之间没有真正区别的事实。<br>

## <font color=gray>**CWE - 90	Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')**</font><br>
中文：**LDAP查询中使用的特殊元素的中和不正确（'LDAP注入'）**<br>
- ### Description
&ensp;该软件使用来自上游组件的外部影响输入构造全部或部分LDAP查询，但它不会中和或不正确地中和可能在将其发送到下游组件时修改预期LDAP查询的特殊元素。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 91	XML Injection (aka Blind XPath Injection)**</font><br>
中文：**XML注入（又称盲注XPath注入）**<br>
- ### Description
&ensp;该软件无法正确中和XML中使用的特殊元素，允许攻击者在终端系统处理之前修改XML的语法，内容或命令。
- ### Extended Description
&ensp;在XML中，特殊元素可以包括保留字或字符，例如“<”，“>”，“”和“＆”，然后可以用于添加新数据或修改XML语法。<br>

## <font color=gray>**CWE - 92	DEPRECATED: Improper Sanitization of Custom Special Characters**</font><br>
中文：**弃用：自定义特殊字符的不当消毒**<br>
- ### Description
&ensp;此条目已被弃用。它最初来自PLOVER，它有时定义“其他”和“杂项”类别，以满足分类法的详尽性要求。在CWE的上下文中，在映射情况下优选使用更抽象的条目。 CWE-75是更合适的映射。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 93	Improper Neutralization of CRLF Sequences ('CRLF Injection')**</font><br>
中文：**CRLF序列的中和不当（'CRLF注射'）**<br>
- ### Description
&ensp;该软件使用CRLF（回车换行）作为特殊元素，例如，分隔行或记录，但它不会中和或错误地中和输入中的CRLF序列。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 94	Improper Control of Generation of Code ('Code Injection')**</font><br>
中文：**代码生成控制不当（'代码注入'）**<br>
- ### Description
&ensp;该软件使用来自上游组件的外部影响输入构造全部或部分代码段，但它不会中和或不正确地中和可能修改预期代码段的语法或行为的特殊元素。
- ### Extended Description
&ensp;当软件允许用户的输入包含代码语法时，攻击者可能以这样的方式制作代码，使其改变软件的预期控制流程。这种改变可能导致任意代码执行。
注射问题包含各种各样的问题 - 所有问题都以非常不同的方式得到缓解。因此，讨论这些弱点的最有效方法是注意将它们归类为注入弱点的独特特征。需要注意的最重要的问题是所有注入问题都有一个共同点 - 即，它们允许将控制平面数据注入用户控制的数据平面。这意味着可以通过合法数据通道发送代码来改变进程的执行，而不使用其他机制。虽然缓冲区溢出和许多其他缺陷涉及使用一些进一步的问题来获得执行，但注入问题仅需要解析数据。这类弱点的最经典的实例是SQL注入和格式字符串漏洞。<br>

## <font color=gray>**CWE - 95	Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')**</font><br>
中文：**动态评估代码中指令的不正确中和（'Eval Injection'）**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但在动态评估调用（例如“eval”）中使用输入之前，它不会中和或不正确地中和代码语法。
- ### Extended Description
&ensp;这可能允许攻击者执行任意代码，或者至少修改可以执行的代码。<br>

## <font color=gray>**CWE - 96	Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')**</font><br>
中文：**静态保存代码中指令的不正确中和（'静态代码注入'）**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但在将输入插入可执行资源（例如库，配置文件或模板）之前，它不会中和或不正确地中和代码语法。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 97	Improper Neutralization of Server-Side Includes (SSI) Within a Web Page**</font><br>
中文：**网页中服务器端包含（SSI）的不正确中和**<br>
- ### Description
&ensp;该软件生成一个网页，但不会中和或不正确地中和可被解释为服务器端包含（SSI）指令的用户可控输入。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 98	Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')**</font><br>
中文：**PHP程序中Include / Require语句的文件名控制不当（'PHP远程文件包含'）**<br>
- ### Description
&ensp;PHP应用程序从上游组件接收输入，但在“require”，“include”或类似函数中使用之前，它不会限制或错误地限制输入。
- ### Extended Description
&ensp;在PHP的某些版本和配置中，这可以允许攻击者指定远程位置的URL，软件将从该位置获取要执行的代码。在与路径遍历相关联的其他情况下，攻击者可以指定可能包含可由PHP解析的可执行语句的本地文件。<br>

## <font color=gray>**CWE - 99	Improper Control of Resource Identifiers ('Resource Injection')**</font><br>
中文：**资源标识符控制不当（'资源注入'）**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但在将输入用作可能在预期控制范围之外的资源的标识符之前，它不限制或不正确地限制输入。
- ### Extended Description
&ensp;满足以下两个条件时会发生资源注入问题：


攻击者可以指定用于访问系统资源的标识符。例如，攻击者可能能够指定要打开的文件的名称的一部分或要使用的端口号。
通过指定资源，攻击者获得了不允许的功能。例如，程序可能使攻击者能够覆盖指定的文件，使用受攻击者控制的配置运行，或者将敏感信息传输到第三方服务器。


这可以使攻击者能够访问或修改受保护的系统资源。<br>

## <font color=gray>**CWE - 102	Struts: Duplicate Validation Forms**</font><br>
中文：**Struts：重复的验证表单**<br>
- ### Description
&ensp;应用程序使用多个具有相同名称的验证表单，这可能会导致Struts验证程序验证程序员不期望的表单。
- ### Extended Description
&ensp;如果两个验证表单具有相同的名称，Struts Validator会任意选择其中一个表单用于输入验证并丢弃另一个表单。这个决定可能与程序员的期望不符，可能导致最终的弱点。此外，它表明验证逻辑不是最新的，并且可以指示存在其他更微妙的验证错误。<br>

## <font color=gray>**CWE - 103	Struts: Incomplete validate() Method Definition**</font><br>
中文：**Struts：不完整的validate（）方法定义**<br>
- ### Description
&ensp;应用程序具有验证器表单，该表单既不定义validate（）方法，也不定义validate（）方法但不调用super.validate（）。
- ### Extended Description
&ensp;如果不调用super.validate（），则验证框架无法根据验证表单检查表单的内容。换句话说，将针对给定表单禁用验证框架。<br>

## <font color=gray>**CWE - 104	Struts: Form Bean Does Not Extend Validation Class**</font><br>
中文：**Struts：Form Bean不会扩展验证类**<br>
- ### Description
&ensp;如果表单bean没有扩展Validator框架的ActionForm子类，它可以将应用程序暴露给与输入验证不足相关的其他弱点。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 105	Struts: Form Field Without Validator**</font><br>
中文：**Struts：没有验证器的表单字段**<br>
- ### Description
&ensp;应用程序的表单字段未通过相应的验证表单进行验证，这可能会引入与输入验证不足相关的其他弱点。
- ### Extended Description
&ensp;即使是单个输入字段省略验证也可能为攻击者提供破坏应用程序所需的余地。尽管J2EE应用程序通常不容易受到内存损坏攻击，但如果J2EE应用程序与不执行数组边界检查的本机代码接口，则攻击者可能能够在J2EE应用程序中使用输入验证错误来启动缓冲区溢出攻击。<br>

## <font color=gray>**CWE - 106	Struts: Plug-in Framework not in Use**</font><br>
中文：**Struts：未使用的插件框架**<br>
- ### Description
&ensp;当应用程序不使用输入验证框架（如Struts Validator）时，引入与输入验证不足相关的弱点的风险更大。
- ### Extended Description
&ensp;未经检查的输入是J2EE应用程序中漏洞的主要原因。未经检查的输入会导致跨站点脚本，进程控制和SQL注入漏洞等。
尽管J2EE应用程序通常不容易受到内存损坏攻击，但如果J2EE应用程序与不执行数组边界检查的本机代码接口，则攻击者可能能够在J2EE应用程序中使用输入验证错误来启动缓冲区溢出攻击。<br>

## <font color=gray>**CWE - 107	Struts: Unused Validation Form**</font><br>
中文：**Struts：未使用的验证表单**<br>
- ### Description
&ensp;未使用的验证表单表明验证逻辑不是最新的。
- ### Extended Description
&ensp;当开发人员删除或重命名动作表单映射时，很容易忘记更新验证逻辑。验证逻辑未得到正确维护的一个迹象是存在未使用的验证表单。<br>

## <font color=gray>**CWE - 108	Struts: Unvalidated Action Form**</font><br>
中文：**Struts：未经验证的行动表格**<br>
- ### Description
&ensp;每个行动表格都必须有相应的验证表格。
- ### Extended Description
&ensp;如果Struts Action Form Mapping指定了一个表单，它必须在Struts Validator下定义一个验证表单。<br>

## <font color=gray>**CWE - 109	Struts: Validator Turned Off**</font><br>
中文：**Struts：验证器关闭**<br>
- ### Description
&ensp;已关闭通过Struts bean自动筛选，这会禁用Struts Validator和自定义验证逻辑。这使应用程序暴露于与输入验证不足相关的其他弱点。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 110	Struts: Validator Without Form Field**</font><br>
中文：**Struts：没有表单字段的验证器**<br>
- ### Description
&ensp;未出现在与其关联的表单中的验证字段表示验证逻辑已过期。
- ### Extended Description
&ensp;开发人员在更改ActionForm类时很容易忘记更新验证逻辑。验证逻辑未得到正确维护的一个迹象是操作表单和验证表单之间的不一致。
尽管J2EE应用程序通常不容易受到内存损坏攻击，但如果J2EE应用程序与不执行数组边界检查的本机代码接口，则攻击者可能能够在J2EE应用程序中使用输入验证错误来启动缓冲区溢出攻击。<br>

## <font color=gray>**CWE - 111	Direct Use of Unsafe JNI**</font><br>
中文：**直接使用不安全的JNI**<br>
- ### Description
&ensp;当Java应用程序使用Java本机接口（JNI）来调用用另一种编程语言编写的代码时，它可以将应用程序暴露给该代码中的弱点，即使这些弱点不能在Java中出现。
- ### Extended Description
&ensp;程序员可能认为理所当然的许多安全功能根本不适用于本机代码，因此您必须仔细检查所有此类代码是否存在潜在问题。用于实现本机代码的语言可能更容易受到缓冲区溢出和其他攻击的影响。本机代码不受运行时环境强制执行的安全功能的保护，例如强类型和数组边界检查。<br>

## <font color=gray>**CWE - 112	Missing XML Validation**</font><br>
中文：**缺少XML验证**<br>
- ### Description
&ensp;该软件接受来自不受信任来源的XML，但不会根据正确的模式验证XML。
- ### Extended Description
&ensp;大多数成功的攻击始于违反程序员的假设。通过接受XML文档而不针对DTD或XML模式验证它，程序员为攻击者留下了一扇门，以便提供意外，不合理或恶意的输入。<br>

## <font color=gray>**CWE - 113	Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')**</font><br>
中文：**HTTP标头中CRLF序列的不正确中和（'HTTP响应拆分'）**<br>
- ### Description
&ensp;软件从上游组件接收数据，但在数据包含在传出HTTP标头中之前，不会中和或错误地中和CR和LF字符。
- ### Extended Description
&ensp;在HTTP标头中包含未经验证的数据允许攻击者指定浏览器呈现的整个HTTP响应。当HTTP请求包含意外CR（回车，也由％0d或\ r \ n）和LF（换行，也由％0a或\ n给出）字符时，服务器可能会响应一个被解释为两个不同的输出流HTTP响应（而不是一个）。攻击者可以控制第二个响应并加载攻击，例如跨站点脚本和缓存中毒攻击。
在以下情况下可能存在HTTP响应拆分弱点：


数据通过不受信任的来源进入Web应用程序，最常见的是HTTP请求。
数据包含在发送给Web用户的HTTP响应标头中，而不会对恶意字符进行验证。<br>

## <font color=gray>**CWE - 114	Process Control**</font><br>
中文：**过程控制**<br>
- ### Description
&ensp;从不受信任的源或不受信任的环境执行命令或加载库可能导致应用程序代表攻击者执行恶意命令（和有效负载）。
- ### Extended Description
&ensp;进程控制漏洞有两种形式：1。攻击者可以更改程序执行的命令：攻击者明确控制命令的内容。 2.攻击者可以更改命令执行的环境：攻击者隐式控制命令的含义。当数据从不受信任的源进入应用程序并且数据用作表示应用程序执行的命令的字符串的一部分时，会发生第一种类型的进程控制漏洞。通过执行该命令，应用程序为攻击者提供了攻击者无法拥有的特权或能力。<br>

## <font color=gray>**CWE - 115	Misinterpretation of Input**</font><br>
中文：**对输入的误解**<br>
- ### Description
&ensp;该软件以安全相关的方式错误解释了来自攻击者或其他产品的输入。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 116	Improper Encoding or Escaping of Output**</font><br>
中文：**输出的编码或转义不正确**<br>
- ### Description
&ensp;该软件准备用于与另一个组件通信的结构化消息，但是数据的编码或转义要么丢失要么不正确。结果，不保留消息的预期结构。
- ### Extended Description
&ensp;不正确的编码或转义可能允许攻击者更改发送到另一个组件的命令，而是插入恶意命令。
大多数软件遵循某种协议，该协议使用结构化消息进行组件之间的通信，例如查询或命令。这些结构化消息可以包含散布有元数据或控制信息的原始数据。例如，“GET /index.html HTTP / 1.1”是一个结构化消息，其中包含一个带有单个参数（“/index.html”）的命令（“GET”）和有关正在使用哪个协议版本的元数据（“HTTP / 1.1" ）。
如果应用程序使用攻击者提供的输入来构造结构化消息而没有正确编码或转义，则攻击者可以插入特殊字符，这些特征将导致数据被解释为控制信息或元数据。因此，接收输出的组件将执行错误的操作，或以其他方式错误地解释数据。<br>

## <font color=gray>**CWE - 117	Improper Output Neutralization for Logs**</font><br>
中文：**日志的输出中和不正确**<br>
- ### Description
&ensp;该软件不会中和或错误地中和写入日志的输出。
- ### Extended Description
&ensp;这可能允许攻击者伪造日志条目或将恶意内容注入日志。
在以下情况下发生日志伪造漏洞：


数据从不受信任的来源进入应用程序。
数据将写入应用程序或系统日志文件。<br>

## <font color=gray>**CWE - 118	Incorrect Access of Indexable Resource ('Range Error')**</font><br>
中文：**可索引资源的不正确访问（“范围错误”）**<br>
- ### Description
&ensp;该软件不限制或不正确地限制使用索引或指针（例如内存或文件）访问的资源边界内的操作。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 119	Improper Restriction of Operations within the Bounds of a Memory Buffer**</font><br>
中文：**内存缓冲区内的操作限制不当**<br>
- ### Description
&ensp;软件对内存缓冲区执行操作，但它可以读取或写入缓冲区预期边界之外的内存位置。
- ### Extended Description
&ensp;某些语言允许直接寻址内存位置，并且不会自动确保这些位置对正在引用的内存缓冲区有效。这可以导致对可能与其他变量，数据结构或内部程序数据相关联的存储器位置执行读或写操作。
因此，攻击者可能能够执行任意代码，更改预期的控制流，读取敏感信息或导致系统崩溃。<br>

## <font color=gray>**CWE - 120	Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')**</font><br>
中文：**缓冲区复制而不检查输入大小（'经典缓冲区溢出'）**<br>
- ### Description
&ensp;程序将输入缓冲区复制到输出缓冲区，而不验证输入缓冲区的大小是否小于输出缓冲区的大小，从而导致缓冲区溢出。
- ### Extended Description
&ensp;当程序试图将更多数据放入缓冲区而不是它可以容纳时，或者当程序试图将数据放入缓冲区边界之外的内存区域时，就会出现缓冲区溢出情况。最简单的错误类型和缓冲区溢出的最常见原因是“经典”情况，程序复制缓冲区而不限制复制的数量。存在其他变体，但经典溢出的存在强烈暗示程序员甚至不考虑最基本的安全保护。<br>

## <font color=gray>**CWE - 121	Stack-based Buffer Overflow**</font><br>
中文：**基于堆栈的缓冲区溢出**<br>
- ### Description
&ensp;基于堆栈的缓冲区溢出条件是被覆盖的缓冲区被分配在堆栈上的条件（即，是局部变量，或者很少是函数的参数）。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 122	Heap-based Buffer Overflow**</font><br>
中文：**基于堆的缓冲区溢出**<br>
- ### Description
&ensp;堆溢出条件是缓冲区溢出，其中可以覆盖的缓冲区在内存的堆部分中分配，通常意味着缓冲区是使用诸如malloc（）之类的例程分配的。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 123	Write-what-where Condition**</font><br>
中文：**写什么地方条件**<br>
- ### Description
&ensp;攻击者能够将任意值写入任意位置的任何情况，通常是缓冲区溢出的结果。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 124	Buffer Underwrite ('Buffer Underflow')**</font><br>
中文：**缓冲区保护（'缓冲下溢'）**<br>
- ### Description
&ensp;软件使用索引或指针写入缓冲区，该索引或指针在缓冲区开始之前引用内存位置。
- ### Extended Description
&ensp;这通常发生在指针或其索引递减到缓冲区之前的位置，指针算术导致有效内存位置开始之前的位置或使用负索引时。<br>

## <font color=gray>**CWE - 125	Out-of-bounds Read**</font><br>
中文：**越界阅读**<br>
- ### Description
&ensp;软件在预期缓冲区的结束或开始之前读取数据。
- ### Extended Description
&ensp;通常，这可能允许攻击者从其他内存位置读取敏感信息或导致崩溃。当代码读取可变数量的数据并假定存在用于停止读取操作的标记（例如字符串中的NUL）时，可能会发生崩溃。预期的哨兵可能不会位于越界内存中，导致过多的数据被读取，从而导致分段错误或缓冲区溢出。软件可以修改索引或执行引用超出缓冲区边界的存储器位置的指针算术。随后的读操作会产生未定义或意外的结果。<br>

## <font color=gray>**CWE - 126	Buffer Over-read**</font><br>
中文：**缓冲区过度读取**<br>
- ### Description
&ensp;软件使用缓冲区访问机制从缓冲区读取，例如在目标缓冲区之后引用内存位置的索引或指针。
- ### Extended Description
&ensp;这通常发生在指针或其索引递增到超出缓冲区边界的位置时，或者当指针算法导致有效内存位置之外的位置时，这一点通常会发生。这可能导致敏感信息的暴露或可能导致崩溃。<br>

## <font color=gray>**CWE - 127	Buffer Under-read**</font><br>
中文：**缓冲区欠读**<br>
- ### Description
&ensp;软件使用缓冲区访问机制从缓冲区读取，例如在目标缓冲区之前引用内存位置的索引或指针。
- ### Extended Description
&ensp;这通常发生在指针或其索引递减到缓冲区之前的位置，指针算术导致有效内存位置开始之前的位置，或者使用负索引时。这可能导致敏感信息的暴露或可能导致崩溃。<br>

## <font color=gray>**CWE - 128	Wrap-around Error**</font><br>
中文：**环绕错误**<br>
- ### Description
&ensp;只要值增加超过其类型的最大值就会发生错误，因此会“绕回”到非常小的，负的或未定义的值。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 129	Improper Validation of Array Index**</font><br>
中文：**数组索引的不正确验证**<br>
- ### Description
&ensp;在计算或使用数组索引时，产品使用不受信任的输入，但产品不验证或错误地验证索引以确保索引引用数组中的有效位置。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 130	Improper Handling of Length Parameter Inconsistency **</font><br>
中文：**长度参数不一致的处理不当**<br>
- ### Description
&ensp;该软件解析格式化的消息或结构，但它不处理或错误地处理与关联数据的实际长度不一致的长度字段。
- ### Extended Description
&ensp;如果攻击者可以操纵与输入相关联的长度参数，使其与输入的实际长度不一致，则可以利用这一点来使目标应用程序以意外的，可能是恶意的方式运行。这样做的一个可能动机是将任意大量的输入传递给应用程序。另一个可能的动机是通过为应用程序的后续属性包含无效数据来修改应用程序状态。这些弱点通常会导致诸如缓冲区溢出和任意代码执行之类的攻击。<br>

## <font color=gray>**CWE - 131	Incorrect Calculation of Buffer Size**</font><br>
中文：**缓冲区大小的计算不正确**<br>
- ### Description
&ensp;软件无法正确计算分配缓冲区时要使用的大小，这可能导致缓冲区溢出。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 132	DEPRECATED (Duplicate): Miscalculated Null Termination**</font><br>
中文：**弃用（重复）：计算的空终止**<br>
- ### Description
&ensp;此条目已被弃用，因为它与CWE-170重复。所有内容均已转移至CWE-170。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 134	Use of Externally-Controlled Format String**</font><br>
中文：**使用外部控制的格式字符串**<br>
- ### Description
&ensp;该软件使用一个接受格式字符串作为参数的函数，但格式字符串来自外部源。
- ### Extended Description
&ensp;当攻击者可以修改外部控制的格式字符串时，这可能导致缓冲区溢出，拒绝服务或数据表示问题。
应该注意的是，在某些情况下，例如国际化，格式字符串集是由设计外部控制的。如果这些格式字符串的来源是可信的（例如，仅包含在只能由系统管理员修改的库文件中），则外部控件本身可能不会构成漏洞。<br>

## <font color=gray>**CWE - 135	Incorrect Calculation of Multi-Byte String Length**</font><br>
中文：**多字节字符串长度的计算不正确**<br>
- ### Description
&ensp;该软件无法正确计算可包含宽字节或多字节字符的字符串长度。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 138	Improper Neutralization of Special Elements**</font><br>
中文：**特殊元素的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和特殊元素，这些元素在被发送到下游组件时可被解释为控制元素或语法标记。
- ### Extended Description
&ensp;大多数语言和协议都有自己的特殊元素，如字符和保留字。这些特殊元素可以带来控制意义。如果软件不阻止外部控制或影响包含这些特殊元素，则程序的控制流程可能会改变。例如，Unix和Windows都将符号<（“小于”）解释为“从文件读取输入”。<br>

## <font color=gray>**CWE - 140	Improper Neutralization of Delimiters**</font><br>
中文：**分隔符的中和不正确**<br>
- ### Description
&ensp;该软件不会中和或错误地中和分隔符。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 141	Improper Neutralization of Parameter/Argument Delimiters**</font><br>
中文：**参数/参数分隔符的中和不正确**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但它不会中和或不正确地中和可能在发送到下游组件时被解释为参数或参数分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 142	Improper Neutralization of Value Delimiters**</font><br>
中文：**价值分隔符的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为值分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 143	Improper Neutralization of Record Delimiters**</font><br>
中文：**记录分隔符的中和不正确**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为记录分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 144	Improper Neutralization of Line Delimiters**</font><br>
中文：**线分隔符的中和不正确**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为行分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 145	Improper Neutralization of Section Delimiters**</font><br>
中文：**截面分隔符的不正确中和**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为段分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。
区段分隔符的一个示例是多部分MIME消息中的边界字符串。在许多情况下，双线分隔符可以用作节分隔符。<br>

## <font color=gray>**CWE - 146	Improper Neutralization of Expression/Command Delimiters**</font><br>
中文：**表达式/命令分隔符的中和不正确**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为表达式或命令分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 147	Improper Neutralization of Input Terminators**</font><br>
中文：**输入终结器的中和不正确**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为输入终止符的特殊元素。
- ### Extended Description
&ensp;例如，“。”在SMTP中表示邮件消息数据的结束，而空字符可用于字符串的结尾。<br>

## <font color=gray>**CWE - 148	Improper Neutralization of Input Leaders**</font><br>
中文：**输入领导者的中和不当**<br>
- ### Description
&ensp;当主要字符或序列（“领导者”）丢失或格式错误时，或者当只允许一个领导者使用多个领导者时，应用程序无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 149	Improper Neutralization of Quoting Syntax**</font><br>
中文：**引用语法的中和不正确**<br>
- ### Description
&ensp;注入应用程序的引号可用于危害系统。在解析数据时，引用的注入/不存在/重复/格式错误的使用可能导致进程采取意外操作。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 150	Improper Neutralization of Escape, Meta, or Control Sequences**</font><br>
中文：**转义，元或控制序列的中和不正确**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和可能被解释为转义，元或控制字符序列的特殊元素，当它们被发送到下游组件时。
- ### Extended Description
&ensp;在解析数据时，注入/缺失/格式错误的分隔符可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 151	Improper Neutralization of Comment Delimiters**</font><br>
中文：**评论分隔符的不正当中和**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但它不会中和或错误地中和特殊元素，这些元素在被发送到下游组件时可以被解释为注释分隔符。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 152	Improper Neutralization of Macro Symbols**</font><br>
中文：**宏符号的中和不正确**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但它不会中和或不正确地中和可能在被发送到下游组件时被解释为宏符号的特殊元素。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 153	Improper Neutralization of Substitution Characters**</font><br>
中文：**替换字符的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为替换字符的特殊元素。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 154	Improper Neutralization of Variable Name Delimiters**</font><br>
中文：**变量名称分隔符的不正确中和**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为变量名称分隔符的特殊元素。
- ### Extended Description
&ensp;在解析数据时，注入的分隔符可能会导致进程采取导致攻击的意外操作。示例：“$”表示环境变量。<br>

## <font color=gray>**CWE - 155	Improper Neutralization of Wildcards or Matching Symbols**</font><br>
中文：**对通配符或匹配符号的不正确中和**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但它不会中和或不正确地中和可能被解释为通配符或匹配符号的特殊元素，当它们被发送到下游组件时。
- ### Extended Description
&ensp;在解析数据时，注入的元素可能会导致进程执行意外操作。<br>

## <font color=gray>**CWE - 156	Improper Neutralization of Whitespace**</font><br>
中文：**空白中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和在将它们发送到下游组件时可被解释为空白的特殊元素。
- ### Extended Description
&ensp;这可以包括空格，标签等。<br>

## <font color=gray>**CWE - 157	Failure to Sanitize Paired Delimiters**</font><br>
中文：**未能消除配对分隔符**<br>
- ### Description
&ensp;该软件无法正确处理用于标记一组实体的开头和结尾的字符，例如括号，括号和大括号。
- ### Extended Description
&ensp;配对分隔符可能包括：


<和>尖括号
（和）括号
{和}大括号
[和]方括号
“ “ 双引号
''单引号<br>

## <font color=gray>**CWE - 158	Improper Neutralization of Null Byte or NUL Character**</font><br>
中文：**空字节或NUL字符的中和不正确**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但是当它们被发送到下游组件时，它不会中和或不正确地中和NUL字符或空字节。
- ### Extended Description
&ensp;在解析数据时，注入的NUL字符或空字节可能导致软件认为输入比实际更早地终止，或者导致输入被误解。然后，这可以用于注入在空字节之后发生的潜在危险输入，或者绕过验证例程和其他保护机制。<br>

## <font color=gray>**CWE - 159	Failure to Sanitize Special Element**</font><br>
中文：**未能消毒特殊元素**<br>
- ### Description
&ensp;这种以攻击为重的类别中的弱点无法正确过滤和解释用户控制输入中的特殊元素，这些元素可能会对软件行为和完整性产生负面影响。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 160	Improper Neutralization of Leading Special Elements**</font><br>
中文：**领导特殊元素的不正当中和**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和可能在发送到下游组件时以意外方式解释的前导特殊元素。
- ### Extended Description
&ensp;在解析数据时，不正确处理前导特殊元素可能会导致进程采取导致攻击的意外操作。<br>

## <font color=gray>**CWE - 161	Improper Neutralization of Multiple Leading Special Elements**</font><br>
中文：**多种主要特殊元素的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和多个可能在发送到下游组件时以意外方式解释的前导特殊元素。
- ### Extended Description
&ensp;在解析数据时，不正确地处理多个前导特殊元素可能会导致进程采取导致攻击的意外操作。<br>

## <font color=gray>**CWE - 162	Improper Neutralization of Trailing Special Elements**</font><br>
中文：**尾随特殊元素的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和可能在发送到下游组件时以意外方式解释的尾随特殊元素。
- ### Extended Description
&ensp;在解析数据时，不正确处理尾随特殊元素可能会导致进程采取导致攻击的意外操作。<br>

## <font color=gray>**CWE - 163	Improper Neutralization of Multiple Trailing Special Elements**</font><br>
中文：**多尾随特殊元素的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和多个尾随特殊元素，这些特殊元素在被发送到下游组件时可能以意外方式解释。
- ### Extended Description
&ensp;在解析数据时，不正确地处理多个尾随特殊元素可能会导致进程采取导致攻击的意外操作。<br>

## <font color=gray>**CWE - 164	Improper Neutralization of Internal Special Elements**</font><br>
中文：**内部特殊元素的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和内部特殊元素，这些特殊元素在被发送到下游组件时可能以意外方式解释。
- ### Extended Description
&ensp;在解析数据时，不正确地处理内部特殊元素可能会导致进程采取导致攻击的意外操作。<br>

## <font color=gray>**CWE - 165	Improper Neutralization of Multiple Internal Special Elements**</font><br>
中文：**多个内部特殊元素的中和不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但它不会中和或不正确地中和多个内部特殊元素，这些特殊元素在被发送到下游组件时可能以意外方式解释。
- ### Extended Description
&ensp;在解析数据时，不正确地处理多个内部特殊元素可能会导致进程采取导致攻击的意外操作。<br>

## <font color=gray>**CWE - 166	Improper Handling of Missing Special Element**</font><br>
中文：**丢失特殊元素的处理不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但是当缺少预期的特殊元素时，它不会处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 167	Improper Handling of Additional Special Element**</font><br>
中文：**附加特殊元素的处理不当**<br>
- ### Description
&ensp;该软件接收来自上游组件的输入，但是当缺少其他意外特殊元素时，它不会处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 168	Improper Handling of Inconsistent Special Elements**</font><br>
中文：**对不一致的特殊元素的处理不当**<br>
- ### Description
&ensp;当两个或多个特殊字符或保留字之间存在不一致时，软件不会处理。
- ### Extended Description
&ensp;此问题的一个示例是，如果配对字符以错误的顺序出现，或者特殊字符未正确嵌套。<br>

## <font color=gray>**CWE - 170	Improper Null Termination**</font><br>
中文：**不适当的空终止**<br>
- ### Description
&ensp;该软件不会终止或错误地终止具有空字符或等效终结符的字符串或数组。
- ### Extended Description
&ensp;空终止错误经常以两种不同的方式发生。逐个错误可能导致空值被写入超出边界，从而导致溢出。或者，程序可能会错误地使用strncpy（）函数调用，这会阻止添加空终止符。其他情况也是可能的。<br>

## <font color=gray>**CWE - 172	Encoding Error**</font><br>
中文：**编码错误**<br>
- ### Description
&ensp;该软件无法正确编码或解码数据，从而导致意外值。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 173	Improper Handling of Alternate Encoding**</font><br>
中文：**替代编码的处理不当**<br>
- ### Description
&ensp;当输入使用对发送输入的控制范围有效的备用编码时，软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 174	Double Decoding of the Same Data**</font><br>
中文：**双重解码相同的数据**<br>
- ### Description
&ensp;该软件对相同的输入进行两次解码，这可能限制在解码操作之间发生的任何保护机制的有效性。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 175	Improper Handling of Mixed Encoding**</font><br>
中文：**混合编码的处理不当**<br>
- ### Description
&ensp;当相同的输入使用多种不同（混合）编码时，软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 176	Improper Handling of Unicode Encoding**</font><br>
中文：**Unicode编码处理不当**<br>
- ### Description
&ensp;当输入包含Unicode编码时，软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 177	Improper Handling of URL Encoding (Hex Encoding)**</font><br>
中文：**URL编码处理不当（十六进制编码）**<br>
- ### Description
&ensp;当全部或部分输入已经过URL编码时，软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 178	Improper Handling of Case Sensitivity**</font><br>
中文：**案例敏感性处理不当**<br>
- ### Description
&ensp;在访问或确定资源属性时，软件无法正确解释区分大小写的差异，从而导致结果不一致。
- ### Extended Description
&ensp;处理不当的区分大小写的数据可能会导致一些可能的后果，包括：


不区分大小写的密码减少了密钥空间的大小，使得暴力攻击更容易
使用备用名称绕过过滤器或访问控制
使用备用名称的多个解释错误。<br>

## <font color=gray>**CWE - 179	Incorrect Behavior Order: Early Validation**</font><br>
中文：**行为顺序不正确：早期验证**<br>
- ### Description
&ensp;软件在应用修改输入的保护机制之前验证输入，这可能允许攻击者通过仅在修改后出现的危险输入绕过验证。
- ### Extended Description
&ensp;在数据经过规范化和清理后，软件需要在适当的时间验证数据。早期验证易受各种操作的影响，这些操作会导致标准化和清洁产生的危险输入。<br>

## <font color=gray>**CWE - 180	Incorrect Behavior Order: Validate Before Canonicalize**</font><br>
中文：**行为顺序不正确：在Canonicalize之前验证**<br>
- ### Description
&ensp;软件在规范化之前验证输入，这阻止软件检测在规范化步骤之后变为无效的数据。
- ### Extended Description
&ensp;攻击者可以使用此方法绕过验证并发起攻击，从而暴露可能会被阻止的弱点，例如注入。<br>

## <font color=gray>**CWE - 181	Incorrect Behavior Order: Validate Before Filter**</font><br>
中文：**行为顺序不正确：在过滤前验证**<br>
- ### Description
&ensp;软件在过滤之前验证数据，这可以防止软件检测到过滤步骤后变为无效的数据。
- ### Extended Description
&ensp;攻击者可以使用此方法绕过验证并发起攻击，从而暴露可能会被阻止的弱点，例如注入。<br>

## <font color=gray>**CWE - 182	Collapse of Data into Unsafe Value**</font><br>
中文：**数据崩溃成不安全的价值**<br>
- ### Description
&ensp;该软件以某种方式过滤数据，导致数据被缩减或“折叠”为违反预期安全属性的不安全值。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 183	Permissive Whitelist**</font><br>
中文：**允许的白名单**<br>
- ### Description
&ensp;应用程序使用可接受值的“白名单”，但白名单包含至少一个不安全值，从而导致产生的弱点。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 184	Incomplete Blacklist**</font><br>
中文：**不完整的黑名单**<br>
- ### Description
&ensp;应用程序使用禁止值的“黑名单”，但黑名单不完整。
- ### Extended Description
&ensp;如果将不完整的黑名单用作安全机制，则软件可能允许非预期的值传递到应用程序逻辑中。<br>

## <font color=gray>**CWE - 185	Incorrect Regular Expression**</font><br>
中文：**正则表达式不正确**<br>
- ### Description
&ensp;该软件以导致数据不正确匹配或比较的方式指定正则表达式。
- ### Extended Description
&ensp;当正则表达式用于过滤或验证等保护机制时，这可能允许攻击者绕过对传入数据的预期限制。<br>

## <font color=gray>**CWE - 186	Overly Restrictive Regular Expression**</font><br>
中文：**过度限制性的正则表达式**<br>
- ### Description
&ensp;正则表达式过于严格，可以防止检测到危险值。
- ### Extended Description
&ensp;这个弱点与正则表达式的复杂性无关。而是关于正则表达式与所有预期的值不匹配。考虑使用正则表达式将可接受的值列入白名单或将不需要的术语列入黑名单。过度限制性的正则表达式错过了一些潜在的安全相关值，导致误报*或*假阴性，这取决于在代码中如何使用正则表达式。考虑表达式/ [0-8] /其中意图是/ [0-9] /。这个表达式并不“复杂”，但是当程序员计划检查它时，值“9”不匹配。<br>

## <font color=gray>**CWE - 187	Partial String Comparison**</font><br>
中文：**部分字符串比较**<br>
- ### Description
&ensp;该软件执行比较，该比较仅在确定是否存在匹配（例如子串）之前检查因子的一部分，从而导致产生的弱点。
- ### Extended Description
&ensp;例如，攻击者可能通过提供与较大的正确密码的关联部分匹配的小密码来成功进行身份验证。<br>

## <font color=gray>**CWE - 188	Reliance on Data/Memory Layout**</font><br>
中文：**依赖于数据/内存布局**<br>
- ### Description
&ensp;该软件对协议数据或内存如何在较低级别组织进行无效假设，从而导致意外的程序行为。
- ### Extended Description
&ensp;更改平台或协议版本时，内存中的数据组织可能会以非预期的方式发生变化。例如，某些体系结构可能将局部变量A和B放在彼此旁边，A顶部;有些人可能会把它们放在一起，B顶在上面;和其他人可能会添加一些填充。填充大小可以变化以确保每个变量与适当的字大小对齐。
在协议实现中，通常计算相对于另一个字段的偏移量以挑选出特定的数据。特殊情况（通常涉及新协议版本）可能会添加以不寻常方式更改数据布局的极端情况。结果可能是实现访问数据包中的非预期字段，将一种类型的数据视为另一种类型的数据。<br>

## <font color=gray>**CWE - 190	Integer Overflow or Wraparound**</font><br>
中文：**整数溢出或环绕**<br>
- ### Description
&ensp;当逻辑假定结果值始终大于原始值时，软件执行可产生整数溢出或环绕的计算。当计算用于资源管理或执行控制时，这可能引入其他弱点。
- ### Extended Description
&ensp;当整数值递增到太大而无法存储在关联表示中的值时，会发生整数溢出或回绕。发生这种情况时，该值可能会换行变为非常小或负数。虽然这可能是在依赖包装的情况下的预期行为，但如果包装是意外的，则会产生安全性后果。如果可以使用用户提供的输入触发整数溢出，则尤其如此。当结果用于控制循环，做出安全决策或确定行为（例如内存分配，复制，连接等）中的偏移量或大小时，这将成为安全关键。<br>

## <font color=gray>**CWE - 191	Integer Underflow (Wrap or Wraparound)**</font><br>
中文：**整数下溢（换行或环绕）**<br>
- ### Description
&ensp;该产品从另一个值中减去一个值，使得结果小于允许的最小整数值，这会产生一个不等于正确结果的值。
- ### Extended Description
&ensp;这可能发生在签名和未签名的情况下。<br>

## <font color=gray>**CWE - 192	Integer Coercion Error**</font><br>
中文：**整数强制误差**<br>
- ### Description
&ensp;整数强制是指与原始数据类型的类型转换，扩展或截断有关的一组缺陷。
- ### Extended Description
&ensp;几个缺陷属于整数强制误差的范畴。在大多数情况下，这些错误本身只会导致可用性和数据完整性问题。但是，在某些情况下，它们可能会导致其他更复杂的安全相关缺陷，例如缓冲区溢出情况。<br>

## <font color=gray>**CWE - 193	Off-by-one Error**</font><br>
中文：**一个错误**<br>
- ### Description
&ensp;产品计算或使用的错误最大值或最小值比正确值多1或少1。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 194	Unexpected Sign Extension**</font><br>
中文：**意外的标志扩展**<br>
- ### Description
&ensp;该软件对一个数字执行操作，使其在转换为更大的数据类型时进行符号扩展。当原始数字为负数时，这会产生意外的值，从而导致产生的弱点。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 195	Signed to Unsigned Conversion Error**</font><br>
中文：**签名到无符号转换错误**<br>
- ### Description
&ensp;该软件使用带符号的基元并对无符号基元执行转换，如果无法使用无符号基元表示有符号基元的值，则可以产生意外值。
- ### Extended Description
&ensp;依赖有符号和无符号数之间的隐式强制转换是危险的，因为结果可能会产生意外的值并违反程序所做的假设。
通常，函数将返回负值以指示失败。当函数的结果用作大小参数时，使用这些负返回值可能会产生意外结果。例如，如果将负大小值传递给标准内存副本或分配函数，则它们将隐式转换为大的无符号值。这可能导致可利用的缓冲区溢出或下溢情况。<br>

## <font color=gray>**CWE - 196	Unsigned to Signed Conversion Error**</font><br>
中文：**无符号转换为有符号转换错误**<br>
- ### Description
&ensp;该软件使用无符号基元并对有符号基元执行强制转换，如果无符号基元的值无法使用有符号基元表示，则可能会产生意外值。
- ### Extended Description
&ensp;尽管问题比签名到无符号转换的频率低，但无符号到签名的转换可能是危险缓冲区保护条件的完美前提，这些条件允许攻击者向下移动堆栈，否则它们可能无法在正常的缓冲区溢出条件下访问。当大的无符号值转换为有符号值，然后用作缓冲区的索引或指针算术时，缓冲区承保经常发生。<br>

## <font color=gray>**CWE - 197	Numeric Truncation Error**</font><br>
中文：**数字截断错误**<br>
- ### Description
&ensp;当基元转换为较小尺寸的基元并且数据在转换中丢失时，会发生截断错误。
- ### Extended Description
&ensp;当基元被转换为较小的基元时，大值的高位比特在转换中丢失，可能导致意外的值不等于原始值。可能需要此值作为缓冲区，循环迭代器或简单必需状态数据的索引。在任何情况下，该值都不可信，系统将处于未定义状态。尽管可以有效地使用该方法来隔离值的低位，但这种用法很少，并且截断通常意味着发生了实现错误。<br>

## <font color=gray>**CWE - 198	Use of Incorrect Byte Ordering**</font><br>
中文：**使用不正确的字节顺序**<br>
- ### Description
&ensp;软件接收来自上游组件的输入，但在处理输入时不考虑字节排序（例如，大端和小端），导致使用不正确的数字或​​值。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 200	Information Exposure**</font><br>
中文：**信息曝光**<br>
- ### Description
&ensp;信息暴露是有意或无意地向未明确授权访问该信息的行为者披露信息。
- ### Extended Description
&ensp;信息要么：


在产品自身的功能中被视为敏感的，例如私人消息;要么
提供有关产品或其环境的信息，这些信息可能在攻击中有用，但攻击者通常无法使用，例如可远程访问的产品的安装路径。


许多信息暴露是结果（例如，PHP脚本错误揭示了程序的完整路径），但它们也可能是主要的（例如加密中的时间差异）。有许多不同类型的问题涉及信息曝光。它们的严重程度可以根据所揭示的信息类型而广泛。<br>

## <font color=gray>**CWE - 201	Information Exposure Through Sent Data**</font><br>
中文：**通过已发送数据的信息曝光**<br>
- ### Description
&ensp;通过发送数据意外暴露敏感信息是指数据的传输，这些数据本身是敏感的，或者在通过标准数据信道进一步利用系统时是有用的。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 202	Exposure of Sensitive Data Through Data Queries**</font><br>
中文：**通过数据查询暴露敏感数据**<br>
- ### Description
&ensp;在尝试保密信息时，攻击者通常可以使用统计信息来推断某些信息。
- ### Extended Description
&ensp;在数据不应该绑定到单个用户的情况下，但是大量用户应该能够进行“擦除”用户身份的查询，则可以获得关于用户的信息 - 例如，通过指定搜索已知对该用户而言唯一的术语。<br>

## <font color=gray>**CWE - 203	Information Exposure Through Discrepancy**</font><br>
中文：**信息暴露通过差异**<br>
- ### Description
&ensp;产品的行为不同或以暴露与产品状态相关的安全相关信息的方式发送不同的响应，例如特定操作是否成功。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 204	Response Discrepancy Information Exposure**</font><br>
中文：**响应差异信息暴露**<br>
- ### Description
&ensp;该软件以允许参与者确定该参与者的控制范围之外的系统状态信息的方式对传入请求提供不同的响应。
- ### Extended Description
&ensp;此问题在身份验证期间经常发生，其中失败登录消息的差异可能允许攻击者确定用户名是否有效。这些暴露可能是无意的（错误的）或有意的（设计）。<br>

## <font color=gray>**CWE - 205	Information Exposure Through Behavioral Discrepancy**</font><br>
中文：**通过行为差异进行信息曝光**<br>
- ### Description
&ensp;产品的行为表明基于（1）产品的内部状态或（2）与同一类别中的其他产品的差异的重要差异。
- ### Extended Description
&ensp;例如，OS指纹识别等攻击在很大程度上依赖于行为和响应差异。<br>

## <font color=gray>**CWE - 206	Information Exposure of Internal State Through Behavioral Inconsistency**</font><br>
中文：**通过行为不一致信息暴露内部状态**<br>
- ### Description
&ensp;产品中的两个单独操作会导致产品以可被攻击者观察到的方式表现不同，并显示有关产品内部状态的安全相关信息，例如特定操作是否成功。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 207	Information Exposure Through an External Behavioral Inconsistency**</font><br>
中文：**信息暴露通过外部行为不一致**<br>
- ### Description
&ensp;该产品的行为与其他类似产品的行为不同，其方式是攻击者可以观察到并暴露与使用哪种产品相关的安全相关信息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 208	Information Exposure Through Timing Discrepancy**</font><br>
中文：**信息暴露通过时间差异**<br>
- ### Description
&ensp;产品中的两个单独的操作需要不同的时间来完成，其方式是对于演员可观察到并且揭示关于产品状态的安全相关信息，例如特定操作是否成功。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 209	Information Exposure Through an Error Message**</font><br>
中文：**信息通过错误消息曝光**<br>
- ### Description
&ensp;该软件会生成一条错误消息，其中包含有关其环境，用户或关联数据的敏感信息。
- ### Extended Description
&ensp;敏感信息本身可能是有价值的信息（例如密码），或者对于发起其他更致命的攻击可能是有用的。如果攻击失败，攻击者可能会使用服务器提供的错误信息来启动另一个更集中的攻击。例如，尝试利用路径遍历弱点（CWE-22）可能会产生已安装应用程序的完整路径名。反过来，这可以用于选择适当数量的“..”序列以导航到目标文件。使用SQL注入（CWE-89）的攻击最初可能不会成功，但错误消息可能会显示格式错误的查询，这会暴露查询逻辑甚至是查询中使用的密码或其他敏感信息。<br>

## <font color=gray>**CWE - 210	Information Exposure Through Self-generated Error Message**</font><br>
中文：**通过自生错误消息进行信息曝光**<br>
- ### Description
&ensp;软件识别错误情况并创建自己的包含敏感信息的诊断或错误消息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 211	Information Exposure Through Externally-Generated Error Message**</font><br>
中文：**通过外部生成的错误消息进行信息暴露**<br>
- ### Description
&ensp;该软件执行触发外部诊断或错误消息的操作，该消息不是由软件直接生成的，例如由软件使用的编程语言解释器生成的错误。该错误可能包含敏感的系统信息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 212	Improper Cross-boundary Removal of Sensitive Data**</font><br>
中文：**不正确的跨境删除敏感数据**<br>
- ### Description
&ensp;该软件使用包含敏感数据的资源，但在与其他控制领域中的actor存储，传输或共享资源之前，它不会正确删除该数据。
- ### Extended Description
&ensp;可能包含敏感数据的资源包括文档，数据包，消息，数据库等。虽然此数据可能对共享资源的单个用户或小组用户有用，但可能需要在资源可以在外部共享之前将其删除受信任的组织。去除过程有时称为清洁或擦洗。
例如，用于编辑文档的软件可能不会删除敏感数据，例如审阅者注释或存储文档的本地路径名。或者，在向Internet站点发出传出请求之前，代理可能不会从标头中删除内部IP地址。<br>

## <font color=gray>**CWE - 213	Intentional Information Exposure**</font><br>
中文：**故意信息曝光**<br>
- ### Description
&ensp;产品的设计或配置明确要求发布可被管理员视为敏感的信息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 214	Information Exposure Through Process Environment**</font><br>
中文：**通过流程环境进行信息曝光**<br>
- ### Description
&ensp;使用敏感参数，环境变量或操作系统上其他进程可以看到的其他元素调用进程。
- ### Extended Description
&ensp;许多操作系统允许用户列出有关其他用户拥有的进程的信息。此信息可能包括命令行参数或环境变量设置。当此数据包含敏感信息（如凭据）时，可能允许其他用户对软件或相关资源发起攻击。<br>

## <font color=gray>**CWE - 215	Information Exposure Through Debug Information**</font><br>
中文：**通过调试信息暴露信息**<br>
- ### Description
&ensp;该应用程序包含调试代码，可以将敏感信息暴露给不受信任的各方。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 216	Containment Errors (Container Errors)**</font><br>
中文：**遏制错误（容器错误）**<br>
- ### Description
&ensp;这试图涵盖在“容器”中包含不正确数据的各种问题。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 217	DEPRECATED: Failure to Protect Stored Data from Modification**</font><br>
中文：**已弃用：未能保护存储数据不被修改**<br>
- ### Description
&ensp;这种弱点已被弃用，因为它融合了许多弱点并使其混淆。以前在这个弱点中涵盖的问题可以在CWE-766和CWE-767中找到。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 218	DEPRECATED (Duplicate): Failure to provide confidentiality for stored data**</font><br>
中文：**已弃用（重复）：未对存储的数据提供机密性**<br>
- ### Description
&ensp;这个弱点已被弃用，因为它与CWE-493重复。所有内容均已转移至CWE-493。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 219	Sensitive Data Under Web Root**</font><br>
中文：**Web Root下的敏感数据**<br>
- ### Description
&ensp;应用程序将敏感数据存储在Web文档根目录下，访问控制不足，这可能使不受信任的各方可以访问它们。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 220	Sensitive Data Under FTP Root**</font><br>
中文：**FTP根目录下的敏感数据**<br>
- ### Description
&ensp;应用程序将敏感数据存储在FTP文档根目录下，访问控制不足，这可能使不受信任方可以访问它。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 221	Information Loss or Omission**</font><br>
中文：**信息丢失或遗漏**<br>
- ### Description
&ensp;该软件不会记录或不正确地记录导致错误决策或妨碍以后分析的安全相关信息。
- ### Extended Description
&ensp;这可能是结果，例如，缓冲区溢出可能会在产品记录事件之前触发崩溃。<br>

## <font color=gray>**CWE - 222	Truncation of Security-relevant Information**</font><br>
中文：**截断安全相关信息**<br>
- ### Description
&ensp;应用程序以可能模糊攻击来源或性质的方式截断安全相关信息的显示，记录或处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 223	Omission of Security-relevant Information**</font><br>
中文：**省略与安全相关的信息**<br>
- ### Description
&ensp;应用程序不会记录或显示对于识别攻击的来源或性质或确定某个操作是否安全非常重要的信息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 224	Obscured Security-relevant Information by Alternate Name**</font><br>
中文：**通过替代名称隐藏安全相关信息**<br>
- ### Description
&ensp;该软件根据受影响实体的备用名称而不是规范名称记录与安全相关的信息。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 225	DEPRECATED (Duplicate): General Information Management Problems**</font><br>
中文：**弃用（重复）：一般信息管理问题**<br>
- ### Description
&ensp;这个弱点可以在CWE-199找到。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 226	Sensitive Information Uncleared Before Release**</font><br>
中文：**敏感信息在发布前未清除**<br>
- ### Description
&ensp;在将该资源提供给另一个控制领域的一方之前，该软件不能完全清除数据结构，文件或其他资源中以前使用的信息。
- ### Extended Description
&ensp;这通常是由新数据产生的，这些新数据不像旧数据那样长，这使得旧数据的一部分仍然可用。在数据长度可变但相关数据结构不可变的其他情况下，可能会发生等效错误。如果在使用后未清除内存，则可能允许非预期的actor在重新分配内存时读取数据。<br>

## <font color=gray>**CWE - 228	Improper Handling of Syntactically Invalid Structure**</font><br>
中文：**句法无效结构的处理不当**<br>
- ### Description
&ensp;产品不处理或错误处理与相关规范相关的语法不完整的输入。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 229	Improper Handling of Values**</font><br>
中文：**不正确的价值处理**<br>
- ### Description
&ensp;如果输入中未提供参数，字段或参数的预期数量的值，或者这些值未定义，则软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 230	Improper Handling of Missing Values**</font><br>
中文：**错误值的处理不当**<br>
- ### Description
&ensp;指定参数，字段或参数名称时，软件不处理或错误处理，但缺少关联值，即它为空，空白或空。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 231	Improper Handling of Extra Values**</font><br>
中文：**对额外值的处理不当**<br>
- ### Description
&ensp;当提供的值多于预期时，软件不会处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 232	Improper Handling of Undefined Values**</font><br>
中文：**未定义值的处理不当**<br>
- ### Description
&ensp;如果未为相关参数，字段或参数名称定义或支持值，则软件不会处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 233	Improper Handling of Parameters**</font><br>
中文：**参数处理不当**<br>
- ### Description
&ensp;如果输入中未提供预期数量的参数，字段或参数，或者这些参数未定义，则软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 234	Failure to Handle Missing Parameter**</font><br>
中文：**无法处理缺失的参数**<br>
- ### Description
&ensp;如果向函数发送的参数太少，该函数仍会从堆栈中弹出预期数量的参数。潜在地，可以在函数中耗尽可变数量的参数。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 235	Improper Handling of Extra Parameters**</font><br>
中文：**额外参数的处理不当**<br>
- ### Description
&ensp;当具有相同名称的参数，字段或参数的数量超过预期量时，软件不会处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 236	Improper Handling of Undefined Parameters**</font><br>
中文：**未定义参数的处理不当**<br>
- ### Description
&ensp;当产品未定义或支持特定参数，字段或参数名称时，软件不会处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 237	Improper Handling of Structural Elements**</font><br>
中文：**结构元素处理不当**<br>
- ### Description
&ensp;该软件不处理或错误处理与复杂结构相关的输入。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 238	Improper Handling of Incomplete Structural Elements**</font><br>
中文：**对不完整结构元素的处理不当**<br>
- ### Description
&ensp;当未完全指定特定结构元素时，软件不处理或错误处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 239	Failure to Handle Incomplete Element**</font><br>
中文：**未能处理不完整的元素**<br>
- ### Description
&ensp;如果未完全指定特定元素，则软件无法正确处理。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 240	Improper Handling of Inconsistent Structural Elements**</font><br>
中文：**对不一致结构元素的处理不当**<br>
- ### Description
&ensp;当两个或多个结构元素应该一致时，软件不会处理或错误处理，但不是。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 241	Improper Handling of Unexpected Data Type**</font><br>
中文：**不正确处理意外数据类型**<br>
- ### Description
&ensp;当特定元素不是预期类型时，软件不处理或错误处理，例如它需要一个数字（0-9），但提供一个字母（A-Z）。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 242	Use of Inherently Dangerous Function**</font><br>
中文：**使用固有危险的功能**<br>
- ### Description
&ensp;该程序调用一个永远不能保证安全工作的函数。
- ### Extended Description
&ensp;无论如何使用，某些功能都会以危险的方式运行。通常在不考虑安全问题的情况下实施此类别中的功能。 gets（）函数是不安全的，因为它不对其输入的大小执行边界检查。攻击者可以轻松地将任意大小的输入发送到gets（）并溢出目标缓冲区。类似地，在读取静态分配的字符数组时，>> operator不安全，因为它不对输入的大小执行边界检查。攻击者可以轻松地将任意大小的输入发送到>>运算符并溢出目标缓冲区。<br>

## <font color=gray>**CWE - 243	Creation of chroot Jail Without Changing Working Directory**</font><br>
中文：**在不改变工作目录的情况下创建chroot监狱**<br>
- ### Description
&ensp;该程序使用chroot（）系统调用来创建一个jail，但之后不会更改工作目录。这不会阻止访问jail之外的文件。
- ### Extended Description
&ensp;chroot（）的不当使用可能允许攻击者逃离chroot监狱。 chroot（）函数调用不会更改进程的当前工作目录，因此在调用chroot（）之后，相对路径仍可能引用chroot jail之外的文件系统资源。<br>

## <font color=gray>**CWE - 244	Improper Clearing of Heap Memory Before Release ('Heap Inspection')**</font><br>
中文：**释放前不正确清除堆内存（'堆检查'）**<br>
- ### Description
&ensp;使用realloc（）来调整存储敏感信息的缓冲区可能会使敏感信息暴露于攻击，因为它不会从内存中删除。
- ### Extended Description
&ensp;如果未从内存中删除敏感数据（如密码或加密密钥），则可能会使用“堆检查”攻击向攻击者公开，该攻击使用内存转储或其他方法读取敏感数据。 realloc（）函数通常用于增加已分配内存块的大小。此操作通常需要将旧存储器块的内容复制到新的更大的块中。此操作使原始块的内容保持不变但程序无法访问，从而阻止程序从内存中擦除敏感数据。如果攻击者以后可以检查内存转储的内容，则可能会暴露敏感数据。<br>

## <font color=gray>**CWE - 245	J2EE Bad Practices: Direct Management of Connections**</font><br>
中文：**J2EE不良做法：直接管理连接**<br>
- ### Description
&ensp;J2EE应用程序直接管理连接，而不是使用容器的连接管理工具。
- ### Extended Description
&ensp;J2EE标准禁止直接管理连接。它要求应用程序使用容器的资源管理工具来获取与资源的连接。每个主要Web应用程序容器都提供池化数据库连接管理作为其资源管理框架的一部分。在应用程序中复制此功能很困难且容易出错，这是J2EE标准禁止的部分原因。<br>

## <font color=gray>**CWE - 246	J2EE Bad Practices: Direct Use of Sockets**</font><br>
中文：**J2EE不良做法：直接使用套接字**<br>
- ### Description
&ensp;J2EE应用程序直接使用套接字而不是使用框架方法调用。
- ### Extended Description
&ensp;当没有更高级别的协议可用时，J2EE标准仅允许将套接字用于与遗留系统通信的目的。编写自己的通信协议需要解决棘手的安全问题。
如果没有安全专家的严格审查，自定义通信协议可能会遇到安全问题。许多相同的问题适用于标准协议的自定义实现。虽然通常有更多资源可用于解决与实施标准协议相关的安全问题，但攻击者也可以使用这些资源。<br>

## <font color=gray>**CWE - 247	DEPRECATED (Duplicate): Reliance on DNS Lookups in a Security Decision**</font><br>
中文：**弃用（重复）：依赖于安全决策中的DNS查找**<br>
- ### Description
&ensp;此条目已被弃用，因为它与CWE-350重复。所有内容均已转移至CWE-350。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 248	Uncaught Exception**</font><br>
中文：**未捕获的异常**<br>
- ### Description
&ensp;从函数抛出异常，但它没有被捕获。
- ### Extended Description
&ensp;未捕获异常时，可能会导致程序崩溃或泄露敏感信息。<br>

## <font color=gray>**CWE - 249	DEPRECATED: Often Misused: Path Manipulation**</font><br>
中文：**弃用：经常被滥用：路径操纵**<br>
- ### Description
&ensp;由于名称混淆以及多个弱点的偶然组合，此条目已被弃用。其大部分内容已转移至CWE-785。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 250	Execution with Unnecessary Privileges**</font><br>
中文：**执行不必要的权限**<br>
- ### Description
&ensp;该软件以高于所需最低级别的权限级别执行操作，这会产生新的弱点或放大其他弱点的后果。
- ### Extended Description
&ensp;可能会暴露新的弱点，因为使用额外的特权（例如root或Administrator）运行可能会禁用操作系统或周围环境执行的正常安全检查。如果在提升权限下运行时，其他预先存在的弱点可能会变成安全漏洞。
权限管理功能可以以一些不太明显的方式运行，并且它们在不同平台上具有不同的怪癖。如果您从一个非root用户转换到另一个非root用户，则这些不一致性尤其明显。信号处理程序和生成的进程在拥有进程的特权下运行，因此如果在信号触发或执行子进程时进程以root身份运行，则信号处理程序或子进程将以root权限运行。<br>

## <font color=gray>**CWE - 252	Unchecked Return Value**</font><br>
中文：**未选中的返回值**<br>
- ### Description
&ensp;软件不检查方法或函数的返回值，这可以防止它检测到意外的状态和条件。
- ### Extended Description
&ensp;两个常见的程序员假设是“这个函数调用永远不会失败”和“这个函数调用失败并不重要”。如果攻击者可以强制该函数失败或以其他方式返回不期望的值，则后续程序逻辑可能导致漏洞，因为该软件不处于程序员假定的状态。例如，如果程序调用函数来删除权限但不检查返回代码以确保成功删除权限，则程序将继续以更高权限运行。<br>

## <font color=gray>**CWE - 253	Incorrect Check of Function Return Value**</font><br>
中文：**函数返回值检查错误**<br>
- ### Description
&ensp;软件错误地检查函数的返回值，这会阻止软件检测错误或异常情况。
- ### Extended Description
&ensp;重要和常见的功能将为其行动的成功返回一些价值。这将提醒程序是否处理由该功能引起的任何错误。<br>

## <font color=gray>**CWE - 256	Unprotected Storage of Credentials**</font><br>
中文：**不受保护的凭证存储**<br>
- ### Description
&ensp;以明文存储密码可能会导致系统受损。
- ### Extended Description
&ensp;当密码以纯文本形式存储在应用程序的属性或配置文件中时，会出现密码管理问题。在配置文件中存储明文密码允许任何能够读取该文件的人访问受密码保护的资源。<br>

## <font color=gray>**CWE - 257	Storing Passwords in a Recoverable Format**</font><br>
中文：**以可恢复的格式存储密码**<br>
- ### Description
&ensp;以可恢复格式存储密码使得它们受到恶意用户的密码重用攻击。实际上，应该注意的是，可恢复的加密密码与明文密码相比没有明显的好处，因为它们不仅可以被恶意攻击者重用，还可以被恶意内部人员重用。如果系统管理员可以直接恢复密码，或对可用信息使用强力搜索，则管理员可以在其他帐户上使用密码。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 258	Empty Password in Configuration File**</font><br>
中文：**配置文件中的空密码**<br>
- ### Description
&ensp;使用空字符串作为密码是不安全的。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 259	Use of Hard-coded Password**</font><br>
中文：**使用硬编码密码**<br>
- ### Description
&ensp;该软件包含一个硬编码密码，用于自己的入站身份验证或外部组件的出站通信。
- ### Extended Description
&ensp;硬编码密码通常会导致严重的身份验证失败，系统管理员很难检测到。一旦检测到，就很难修复，因此管理员可能会被迫完全禁用该产品。主要有两种变化：

入站：该软件包含一个检查硬编码密码的身份验证机制。
出站：软件连接到另一个系统或组件，它包含用于连接到该组件的硬编码密码。

在入站变体中，将创建默认管理帐户，并将简单密码硬编码到产品中并与该帐户关联。此硬编码密码对于产品的每次安装都是相同的，并且系统管理员通常无法在不手动修改程序或修补软件的情况下更改或禁用密码。如果密码被发现或发布（在Internet上很常见），那么任何知道此密码的人都可以访问该产品。最后，由于软件的所有安装都具有相同的密码，即使在不同的组织中，也可以实现诸如蠕虫之类的大规模攻击。
Outbound变体适用于使用后端服务进行身份验证的前端系统。后端服务可能需要一个可以轻松发现的固定密码。程序员可以简单地将这些后端凭证硬编码到前端软件中。该程序的任何用户都可以提取密码。具有硬编码密码的客户端系统构成了更大的威胁，因为从二进制文件中提取密码通常非常简单。<br>

## <font color=gray>**CWE - 260	Password in Configuration File**</font><br>
中文：**配置文件中的密码**<br>
- ### Description
&ensp;该软件将密码存储在配置文件中，该配置文件可能对不知道密码的演员可访问。
- ### Extended Description
&ensp;这可能导致使用密码的系统受到损害。攻击者可以访问此文件并了解存储的密码，或者更糟糕的是，将密码更改为他们选择的密码。<br>

## <font color=gray>**CWE - 261	Weak Cryptography for Passwords**</font><br>
中文：**密码弱密码学**<br>
- ### Description
&ensp;使用简单编码隐藏密码不会保护密码。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 262	Not Using Password Aging**</font><br>
中文：**不使用密码时效**<br>
- ### Description
&ensp;如果没有适当的机制来管理密码老化，用户将无法及时更新密码。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 263	Password Aging with Long Expiration**</font><br>
中文：**长期过期的密码时效**<br>
- ### Description
&ensp;允许密码老化未经检查可能导致密码完整性降低。
- ### Extended Description
&ensp;正如忽略包含管理密码老化的功能是危险的，因此允许密码老化继续未选中。密码必须具有最长寿命，之后用户需要使用新的不同密码进行更新。<br>

## <font color=gray>**CWE - 266	Incorrect Privilege Assignment**</font><br>
中文：**权限分配不正确**<br>
- ### Description
&ensp;产品错误地将特权分配给特定的actor，为该actor创建一个非预期的控制范围。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 267	Privilege Defined With Unsafe Actions**</font><br>
中文：**使用不安全操作定义的权限**<br>
- ### Description
&ensp;特定的权限，角色，功能或权限可用于执行非预期的不安全操作，即使将其分配给正确的实体也是如此。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 268	Privilege Chaining**</font><br>
中文：**特权链接**<br>
- ### Description
&ensp;可以以允许实体执行不允许没有该组合的不安全动作的方式组合两个不同的特权，角色，功能或权限。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 269	Improper Privilege Management**</font><br>
中文：**权限管理不当**<br>
- ### Description
&ensp;该软件未正确分配，修改，跟踪或检查演员的权限，从而为该演员创建了一个非预期的控制范围。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 270	Privilege Context Switching Error**</font><br>
中文：**特权上下文切换错误**<br>
- ### Description
&ensp;当软件在具有不同权限或控制范围的不同上下文之间切换时，该软件无法正确管理权限。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 271	Privilege Dropping / Lowering Errors**</font><br>
中文：**权限下降/降低错误**<br>
- ### Description
&ensp;在将资源控制权交给没有这些权限的actor之前，该软件不会删除权限。
- ### Extended Description
&ensp;在某些情况下，使用提升权限执行的系统将切换进程/文件/等。到另一个进程或用户。如果未降低实体的权限，则提升的权限会在整个系统中传播，并可能传播给攻击者。<br>

## <font color=gray>**CWE - 272	Least Privilege Violation**</font><br>
中文：**最低权限违规**<br>
- ### Description
&ensp;执行操作后，应立即删除执行chroot（）等操作所需的提升权限级别。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 273	Improper Check for Dropped Privileges**</font><br>
中文：**不正确检查已删除的权限**<br>
- ### Description
&ensp;该软件尝试删除权限，但不检查或错误检查以查看删除是否成功。
- ### Extended Description
&ensp;如果删除失败，软件将继续使用提升的权限运行，这可能会为非特权用户提供额外的访问权限。<br>

## <font color=gray>**CWE - 274	Improper Handling of Insufficient Privileges**</font><br>
中文：**权利不足的处理不当**<br>
- ### Description
&ensp;当软件没有足够的权限执行操作时，软件不会处理或错误处理，从而导致产生的缺陷。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 276	Incorrect Default Permissions**</font><br>
中文：**默认权限不正确**<br>
- ### Description
&ensp;安装后，该软件为将其公开给非预期的actor的对象设置了不正确的权限。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 277	Insecure Inherited Permissions**</font><br>
中文：**不安全的继承权限**<br>
- ### Description
&ensp;产品定义一组不安全的权限，这些权限由程序创建的对象继承。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 278	Insecure Preserved Inherited Permissions**</font><br>
中文：**不安全的保留继承权限**<br>
- ### Description
&ensp;产品继承了一组对象的不安全权限，例如从存档文件复制时，没有用户意识或参与。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 279	Incorrect Execution-Assigned Permissions**</font><br>
中文：**执行分配的权限不正确**<br>
- ### Description
&ensp;在执行时，软件以违反用户指定的预期权限的方式设置对象的权限。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 280	Improper Handling of Insufficient Permissions or Privileges **</font><br>
中文：**对权限或权限不足的处理不当**<br>
- ### Description
&ensp;当应用程序没有足够的权限访问其权限所指定的资源或功能时，应用程序不会处理或错误处理。这可能导致它遵循可能使应用程序处于无效状态的意外代码路径。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 281	Improper Preservation of Permissions**</font><br>
中文：**权限保护不当**<br>
- ### Description
&ensp;在复制，还原或共享对象时，该软件不保留权限或错误地保留权限，这可能导致它们具有比预期更少的限制权限。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 282	Improper Ownership Management**</font><br>
中文：**所有权管理不当**<br>
- ### Description
&ensp;该软件分配了错误的所有权，或者没有正确验证对象或资源的所有权。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 283	Unverified Ownership**</font><br>
中文：**未经证实的所有权**<br>
- ### Description
&ensp;该软件未正确验证关键资源是否由适当的实体拥有。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 284	Improper Access Control**</font><br>
中文：**访问控制不当**<br>
- ### Description
&ensp;该软件不限制或不正确地限制对未授权演员的资源访问。
- ### Extended Description
&ensp;访问控制涉及使用多种保护机制，例如：

身份验证（证明演员的身份）
授权（确保给定的actor可以访问资源），以及
问责制（跟踪已执行的活动）

当任何机制未应用或以其他方式失败时，攻击者可以通过获取权限，读取敏感信息，执行命令，逃避检测等来危害软件的安全性。
有两种不同的行为可能会引入访问控制缺陷：


规范：为用户或资源明确指定了不正确的权限，权限，所有权等（例如，将密码文件设置为可全局写入，或​​为访客用户提供管理员功能）。此操作可由程序或管理员执行。
强制执行：该机制包含的错误会阻止它正确执行指定的访问控制要求（例如，允许用户指定自己的权限，或允许语法错误的ACL产生不安全的设置）。此问题发生在程序本身内，因为它实际上并未强制执行管理员指定的预期安全策略。<br>

## <font color=gray>**CWE - 285	Improper Authorization**</font><br>
中文：**授权不当**<br>
- ### Description
&ensp;当actor尝试访问资源或执行操作时，该软件不执行或错误地执行授权检查。
- ### Extended Description
&ensp;假设具有给定身份的用户，授权是基于用户的权限和适用于资源的任何权限或其他访问控制规范来确定该用户是否可以访问给定资源的过程。
当访问控制检查未一致地应用 - 或根本不应用 - 用户能够访问数据或执行不应被允许执行的操作。这可能导致各种各样的问题，包括信息泄露，拒绝服务和任意代码执行。<br>

## <font color=gray>**CWE - 286	Incorrect User Management**</font><br>
中文：**用户管理不正确**<br>
- ### Description
&ensp;该软件无法在其环境中正确管理用户。
- ### Extended Description
&ensp;可以将用户分配给错误的权限组（类），从而导致对敏感对象的非预期访问权限。<br>

## <font color=gray>**CWE - 287	Improper Authentication**</font><br>
中文：**身份验证不正确**<br>
- ### Description
&ensp;当演员声称拥有特定身份时，该软件不会证明或证明该声明是正确的。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 288	Authentication Bypass Using an Alternate Path or Channel**</font><br>
中文：**使用备用路径或通道进行身份验证旁路**<br>
- ### Description
&ensp;产品需要身份验证，但产品具有不需要身份验证的备用路径或通道。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 289	Authentication Bypass by Alternate Name**</font><br>
中文：**身份验证绕过备用名称**<br>
- ### Description
&ensp;该软件基于正在访问的资源的名称或执行访问的actor的名称执行身份验证，但它没有正确检查该资源或actor的所有可能名称。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 290	Authentication Bypass by Spoofing**</font><br>
中文：**通过欺骗进行身份验证绕过**<br>
- ### Description
&ensp;这种以攻击为中心的弱点是由不正确实施的受欺骗攻击的身份验证方案引起的。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 291	Reliance on IP Address for Authentication**</font><br>
中文：**依赖于身份验证的IP地址**<br>
- ### Description
&ensp;该软件使用IP地址进行身份验证。
- ### Extended Description
&ensp;IP地址很容易被欺骗。攻击者可以伪造他们发送的数据包的源IP地址，但响应数据包将返回伪造的IP地址。要查看响应数据包，攻击者必须嗅探受害者计算机和伪造IP地址之间的流量。为了完成所需的嗅探，攻击者通常会尝试将自己定位在与受害者计算机相同的子网上。攻击者可以通过使用源路由来规避此要求，但是今天在大部分Internet上都禁用了源路由。总之，IP地址验证可以是身份验证方案的有用部分，但它不应该是身份验证所需的单一因素。<br>

## <font color=gray>**CWE - 292	DEPRECATED (Duplicate): Trusting Self-reported DNS Name**</font><br>
中文：**DEPRECATED（重复）：信任自我报告的DNS名称**<br>
- ### Description
&ensp;此条目已被弃用，因为它与CWE-350重复。所有内容均已转移至CWE-350。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 293	Using Referer Field for Authentication**</font><br>
中文：**使用Referer字段进行身份验证**<br>
- ### Description
&ensp;HTTP请求中的referer字段可以很容易地修改，因此不是消息完整性检查的有效方法。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 294	Authentication Bypass by Capture-replay**</font><br>
中文：**身份验证绕过Capture-replay**<br>
- ### Description
&ensp;当软件设计使恶意用户可以通过将其重播到相关服务器以获得与原始消息相同的效果（或稍作更改）来嗅探网络流量并绕过身份验证时，存在捕获重放缺陷。
- ### Extended Description
&ensp;捕获重放攻击很常见，如果没有加密技术，很难打败。它们是网络注入攻击的一个子集，它依赖于观察先前发送的有效命令，然后在必要时稍微更改它们并将相同的命令重新发送到服务器。<br>

## <font color=gray>**CWE - 295	Improper Certificate Validation**</font><br>
中文：**证书验证不正确**<br>
- ### Description
&ensp;该软件不验证或错误验证证书。
- ### Extended Description
&ensp;当证书无效或恶意时，它可能允许攻击者通过使用中间人（MITM）攻击欺骗可信实体。该软件可能连接到恶意主机，同时认为它是可信主机，或者软件可能被欺骗接受看似来自可信主机的欺骗数据。<br>

## <font color=gray>**CWE - 296	Improper Following of a Certificate's Chain of Trust**</font><br>
中文：**不正确地遵循证书的信任链**<br>
- ### Description
&ensp;该软件不遵循或错误地遵循证书的信任链回到受信任的根证书，从而导致与该证书关联的任何资源的不正确信任。
- ### Extended Description
&ensp;如果系统不遵循证书对根服务器的信任链，则证书将失去作为信任度量的所有有用性。从本质上讲，从证书中获得的信任来自信任链 - 在该列表的末尾有一个信誉良好的可信实体。最终用户必须信任该信誉良好的来源，并且这个信誉良好的来源必须通过证书媒介担保相关资源。
在某些情况下，这种信任遍历了几个互相担保的实体。最终用户信任的实体位于此信任链的一端，而证书挥舞资源位于链的另一端。如果用户在其中一个信任链的末尾收到证书，然后继续仅检查链中的第一个链接，则不会导出真正的信任，因为必须遍历整个链到可信来源以验证证书。
可以通过多种方式破坏信任链，包括但不限于：


链中的任何证书都是自签名的，除非它是根。
并非每个中间证书都会被检查，从原始证书一直到根证书。
中间的CA签名证书没有预期的基本约束或其他重要扩展。
根证书已被泄露或授权给错误的一方。<br>

## <font color=gray>**CWE - 297	Improper Validation of Certificate with Host Mismatch**</font><br>
中文：**主机不匹配的证书验证不正确**<br>
- ### Description
&ensp;该软件与提供证书的主机通信，但该软件未正确确保证书实际与该主机关联。
- ### Extended Description
&ensp;即使证书格式良好，签名并遵循信任链，它也可能只是与软件交互的站点不同的站点的有效证书。如果未正确检查证书的特定于主机的数据（例如主题中的公用名（CN）或X.509证书的主题备用名称（SAN）扩展名），则可能会出现重定向或欺骗攻击允许具有有效证书的恶意主机提供数据，模拟可信主机。为了确保数据完整性，证书必须有效，并且必须与正在访问的站点相关。
即使软件试图检查主机名，仍然可能错误地检查主机名。例如，攻击者可以创建一个名称以可信名称开头，后跟NUL字节的证书，这可能导致某些基于字符串的比较仅检查包含受信任名称的部分。
即使软件使用证书固定，如果软件在固定证书时未验证主机名，也会出现此弱点。<br>

## <font color=gray>**CWE - 298	Improper Validation of Certificate Expiration**</font><br>
中文：**证书过期的验证不正确**<br>
- ### Description
&ensp;证书过期未经过验证或未正确验证，因此可能会将信任分配给因年龄而被放弃的证书。
- ### Extended Description
&ensp;如果不考虑证书的到期，则不一定通过它传达信任。因此，无法验证证书的有效性，并且证书的所有好处都将丢失。<br>

## <font color=gray>**CWE - 299	Improper Check for Certificate Revocation**</font><br>
中文：**不正确的检查证书撤销**<br>
- ### Description
&ensp;该软件不检查或错误地检查证书的撤销状态，这可能导致它使用已被泄露的证书。
- ### Extended Description
&ensp;对证书撤销进行不正确的检查是一个比相关证书失败更严重的缺陷。这是因为使用任何撤销的证书几乎肯定是恶意的。证书撤销的最常见原因是有问题的系统遭到破坏，结果是没有合法的服务器将使用撤销的证书，除非它们非常不同步。<br>

## <font color=gray>**CWE - 300	Channel Accessible by Non-Endpoint ('Man-in-the-Middle')**</font><br>
中文：**非端点可访问的频道（'中间人'）**<br>
- ### Description
&ensp;该产品不能充分验证通信信道两端的参与者的身份，或者不能充分确保信道的完整性，从而允许信道被非端点的参与者访问或影响。
- ### Extended Description
&ensp;为了在双方之间建立安全通信，充分验证通信信道每端的实体身份通常很重要。验证不充分或不一致可能导致通信实体的识别不充分或不正确。这可能会产生负面影响，例如信道另一端的实体信任错位。攻击者可以通过插入通信实体和伪装成原始实体来利用它。在没有足够的身份验证的情况下，这样的攻击者可以窃听并可能修改原始实体之间的通信。<br>

## <font color=gray>**CWE - 301	Reflection Attack in an Authentication Protocol**</font><br>
中文：**身份验证协议中的反射攻击**<br>
- ### Description
&ensp;如果恶意用户可以使用目标计算机模拟受信任的用户，则简单身份验证协议会受到反射攻击。
- ### Extended Description
&ensp;相互认证协议要求每一方通过用预共享密钥加密来响应另一方的随机质询。然而，这些协议通常使用相同的预共享密钥来与多个不同实体进行通信。恶意用户或攻击者可以通过对协议采用反射攻击来轻松地破坏此协议，而无需拥有正确的密钥。<br>

## <font color=gray>**CWE - 302	Authentication Bypass by Assumed-Immutable Data**</font><br>
中文：**认证绕过假定不可变数据**<br>
- ### Description
&ensp;身份验证方案或实现使用假定为不可变的关键数据元素，但可由攻击者控制或修改。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 303	Incorrect Implementation of Authentication Algorithm**</font><br>
中文：**验证算法的不正确实现**<br>
- ### Description
&ensp;软件的要求决定了使用已建立的认证算法，但算法的实现是不正确的。
- ### Extended Description
&ensp;这种不正确的实现可能允许绕过身份验证。<br>

## <font color=gray>**CWE - 304	Missing Critical Step in Authentication**</font><br>
中文：**缺少身份验证的关键步骤**<br>
- ### Description
&ensp;该软件实现了一种身份验证技术，但它跳过了削弱技术的步骤。
- ### Extended Description
&ensp;身份验证技术应遵循精确定义它们的算法，否则可以绕过身份验证或更容易受到暴力攻击。<br>

## <font color=gray>**CWE - 305	Authentication Bypass by Primary Weakness**</font><br>
中文：**主要弱点的身份验证旁路**<br>
- ### Description
&ensp;验证算法是合理的，但是实现的机制可以被旁路，因为单独的弱点是认证错误的主要缺陷。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 306	Missing Authentication for Critical Function**</font><br>
中文：**缺少关键功能的身份验证**<br>
- ### Description
&ensp;该软件不对需要可证明的用户身份或消耗大量资源的功能执行任何身份验证。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 307	Improper Restriction of Excessive Authentication Attempts**</font><br>
中文：**过度认证尝试的不当限制**<br>
- ### Description
&ensp;该软件没有实施足够的措施来防止在短时间内发生多次失败的身份验证尝试，使其更容易受到暴力攻击。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 308	Use of Single-factor Authentication**</font><br>
中文：**使用单因素身份验证**<br>
- ### Description
&ensp;与双因素身份验证方案的优势相比，使用单因素身份验证可能会导致不必要的危害风险。
- ### Extended Description
&ensp;虽然使用多种身份验证方案只是在身份验证之上进行了更多的复杂化，但拥有这种冗​​余度量是非常有价值的。在互联网上使用弱，重用和通用密码是猖獗的。如果没有多个身份验证方案的额外保护，单个错误可能会导致帐户泄露。因此，如果可能有多种方案且易于使用，则应实施和要求它们。<br>

## <font color=gray>**CWE - 309	Use of Password System for Primary Authentication**</font><br>
中文：**使用密码系统进行主要验证**<br>
- ### Description
&ensp;使用密码系统作为主要的认证手段可能存在若干缺陷或缺点，每个缺陷或缺点都会降低机制的有效性。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 311	Missing Encryption of Sensitive Data**</font><br>
中文：**缺少敏感数据的加密**<br>
- ### Description
&ensp;在存储或传输之前，该软件不会加密敏感或关键信息。
- ### Extended Description
&ensp;缺乏适当的数据加密传递了正确实施加密所传达的机密性，完整性和责任性的保证。<br>

## <font color=gray>**CWE - 312	Cleartext Storage of Sensitive Information**</font><br>
中文：**明文存储敏感信息**<br>
- ### Description
&ensp;应用程序将敏感信息以明文形式存储在可能可供另一个控制领域访问的资源中。
- ### Extended Description
&ensp;由于信息以明文形式存储，因此攻击者可能会阅读它。即使以非人类可读的方式对信息进行编码，某些技术也可以确定正在使用哪种编码，然后对信息进行解码。<br>

## <font color=gray>**CWE - 313	Cleartext Storage in a File or on Disk**</font><br>
中文：**文件或磁盘上的明文存储**<br>
- ### Description
&ensp;应用程序将敏感信息以明文形式存储在文件或磁盘上。
- ### Extended Description
&ensp;敏感信息可由具有文件访问权限的攻击者读取，或者通过对原始磁盘的物理或管理员访问权限读取。即使以非人类可读的方式对信息进行编码，某些技术也可以确定正在使用哪种编码，然后对信息进行解码。<br>

## <font color=gray>**CWE - 314	Cleartext Storage in the Registry**</font><br>
中文：**注册表中的明文存储**<br>
- ### Description
&ensp;应用程序将敏感信息以明文形式存储在注册表中。
- ### Extended Description
&ensp;攻击者可以通过访问注册表项来读取信息。即使以非人类可读的方式对信息进行编码，某些技术也可以确定正在使用哪种编码，然后对信息进行解码。<br>

## <font color=gray>**CWE - 315	Cleartext Storage of Sensitive Information in a Cookie**</font><br>
中文：**明文在Cookie中存储敏感信息**<br>
- ### Description
&ensp;应用程序将敏感信息以明文形式存储在cookie中。
- ### Extended Description
&ensp;攻击者可以使用广泛使用的工具来查看cookie并读取敏感信息。即使以非人类可读的方式对信息进行编码，某些技术也可以确定正在使用哪种编码，然后对信息进行解码。<br>

## <font color=gray>**CWE - 316	Cleartext Storage of Sensitive Information in Memory**</font><br>
中文：**明文中存储敏感信息的明文**<br>
- ### Description
&ensp;应用程序将敏感信息以明文形式存储在内存中。
- ### Extended Description
&ensp;敏感内存可能会保存到磁盘，存储在核心转储中，或者如果应用程序崩溃仍未清除，或者程序员在释放内存之前未正确清除内存。
可以说，这些问题通常只有具有管理员权限的人才可以利用。但是，交换可能会导致内存写入磁盘并使之后可以进行物理攻击。核心转储文件可能具有不安全的权限，或存储在不受信任的人可访问的归档文件中。或者，由于另一个弱点，未清除的敏感内存可能会无意中暴露给攻击者。<br>

## <font color=gray>**CWE - 317	Cleartext Storage of Sensitive Information in GUI**</font><br>
中文：**GUI中敏感信息的明文存储**<br>
- ### Description
&ensp;应用程序在GUI中以明文形式存储敏感信息。
- ### Extended Description
&ensp;通过使用API​​直接访问GUI对象（如窗口和菜单），攻击者通常可以从GUI获取数据，即使是隐藏的。即使以非人类可读的方式对信息进行编码，某些技术也可以确定正在使用哪种编码，然后对信息进行解码。<br>

## <font color=gray>**CWE - 318	Cleartext Storage of Sensitive Information in Executable**</font><br>
中文：**在可执行文件中明确存储敏感信息**<br>
- ### Description
&ensp;应用程序将敏感信息以明文形式存储在可执行文件中。
- ### Extended Description
&ensp;攻击者可以对二进制代码进行逆向工程以获取秘密数据当明文是纯ASCII时，这一点尤其容易。即使以非人类可读的方式对信息进行编码，某些技术也可以确定正在使用哪种编码，然后对信息进行解码。<br>

## <font color=gray>**CWE - 319	Cleartext Transmission of Sensitive Information**</font><br>
中文：**明文传播敏感信息**<br>
- ### Description
&ensp;该软件以通信渠道的明文形式传输敏感或安全关键数据，这些数据可能被未经授权的参与者嗅探。
- ### Extended Description
&ensp;在数据传输期间，攻击者可以“嗅探”许多通信信道。例如，任何有权访问网络接口的攻击者都可以嗅探网络流量。这大大降低了攻击者利用的难度。<br>

## <font color=gray>**CWE - 321	Use of Hard-coded Cryptographic Key**</font><br>
中文：**使用硬编码密码密钥**<br>
- ### Description
&ensp;使用硬编码的加密密钥显着增加了可以恢复加密数据的可能性。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 322	Key Exchange without Entity Authentication**</font><br>
中文：**没有实体身份验证的密钥交换**<br>
- ### Description
&ensp;该软件与演员进行密钥交换，而不验证该演员的身份。
- ### Extended Description
&ensp;执行密钥交换将保持两个实体之间发送的信息的完整性，但这并不能保证实体是他们声称的实体。这可能会导致一系列“中间人”攻击。通常，这涉及受害客户端，该客户端联系冒充受信任服务器的恶意服务器。如果客户端跳过身份验证或忽略身份验证失败，则恶意服务器可以从用户请求身份验证信息。然后，恶意服务器可以使用此身份验证信息使用受害者的凭据登录受信任的服务器，嗅探受害者和受信任服务器之间的流量等。<br>

## <font color=gray>**CWE - 323	Reusing a Nonce, Key Pair in Encryption**</font><br>
中文：**在加密中重用Nonce，密钥对**<br>
- ### Description
&ensp;Nonce应该用于当前场合并且只能使用一次。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 324	Use of a Key Past its Expiration Date**</font><br>
中文：**在过期日期之后使用密钥**<br>
- ### Description
&ensp;该产品使用加密密钥或密码超过其到期日期，通过增加针对该密钥的破解攻击的时间窗口，显着降低了其安全性。
- ### Extended Description
&ensp;虽然密钥的到期并不一定确保它们被泄露，但是长时间使用的密钥具有降低的完整性概率是一个重要的问题。因此，在与其强度成比例的时间段内更换按键非常重要。<br>

## <font color=gray>**CWE - 325	Missing Required Cryptographic Step**</font><br>
中文：**缺少必需的加密步骤**<br>
- ### Description
&ensp;该软件没有在加密算法中实现所需的步骤，导致加密比该算法所公布的更弱。
- ### Extended Description
&ensp;加密实现应遵循精确定义它们的算法，否则加密可能比预期的要弱。<br>

## <font color=gray>**CWE - 326	Inadequate Encryption Strength**</font><br>
中文：**加密强度不足**<br>
- ### Description
&ensp;该软件使用理论上合理的加密方案存储或传输敏感数据，但不足以达到所需的保护级别。
- ### Extended Description
&ensp;弱加密方案可能会遭受暴力攻击，这些攻击有可能成功使用当前的攻击方法和资源。<br>

## <font color=gray>**CWE - 327	Use of a Broken or Risky Cryptographic Algorithm**</font><br>
中文：**使用破碎或危险的密码算法**<br>
- ### Description
&ensp;使用破坏或有风险的加密算法是不必要的风险，可能导致敏感信息的暴露。
- ### Extended Description
&ensp;使用非标准算法是危险的，因为确定的攻击者可能能够破坏算法并破坏任何受保护的数据。可能存在众所周知的技术来破坏算法。<br>

## <font color=gray>**CWE - 328	Reversible One-Way Hash**</font><br>
中文：**可逆的单向哈希**<br>
- ### Description
&ensp;该产品使用散列算法生成哈希值，该哈希值可用于确定原始输入，或查找可生成相同哈希的输入，比蛮力技术更有效。
- ### Extended Description
&ensp;当哈希用于需要单向属性保持的安全算法时，这种弱点尤其危险。例如，如果身份验证系统获取传入密码并生成哈希值，则将哈希值与其身份验证数据库中存储的另一个哈希值进行比较，然后创建冲突的能力可能允许攻击者提供生成的备用密码相同的目标哈希，绕过身份验证。<br>

## <font color=gray>**CWE - 329	Not Using a Random IV with CBC Mode**</font><br>
中文：**不使用具有CBC模式的随机IV**<br>
- ### Description
&ensp;不使用具有密码块链接（CBC）模式的随机初始化向量（IV）导致算法易受字典攻击。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 330	Use of Insufficiently Random Values**</font><br>
中文：**使用不充分的随机值**<br>
- ### Description
&ensp;软件可能在安全上下文中使用不完全随机的数字或值，这取决于不可预测的数字。
- ### Extended Description
&ensp;当软件在需要不可预测性的上下文中生成可预测值时，攻击者可能猜测将生成的下一个值，并使用此猜测来模拟其他用户或访问敏感信息。<br>

## <font color=gray>**CWE - 331	Insufficient Entropy**</font><br>
中文：**熵不足**<br>
- ### Description
&ensp;该软件使用产生不足熵的算法或方案，留下比其他更可能发生的模式或值集群。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 332	Insufficient Entropy in PRNG**</font><br>
中文：**PRNG中的熵不足**<br>
- ### Description
&ensp;伪随机数发生器（PRNG）可用或使用的熵的缺乏可能是稳定性和安全性威胁。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 333	Improper Handling of Insufficient Entropy in TRNG**</font><br>
中文：**TRNG中熵不足的处理不当**<br>
- ### Description
&ensp;真随机数发生器（TRNG）通常具有有限的熵源，因此可能失败或阻塞。
- ### Extended Description
&ensp;可以生成真随机数的速率是有限的。重要的是，只有在安全需要时才使用它们。<br>

## <font color=gray>**CWE - 334	Small Space of Random Values**</font><br>
中文：**随机值的小空间**<br>
- ### Description
&ensp;可能的随机值的数量小于产品所需的数量，使其更容易受到强力攻击。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 335	Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)**</font><br>
中文：**伪随机数发生器（PRNG）中种子的使用不正确**<br>
- ### Description
&ensp;该软件使用伪随机数发生器（PRNG），不能正确管理种子。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 336	Same Seed in Pseudo-Random Number Generator (PRNG)**</font><br>
中文：**伪随机数发生器（PRNG）中的相同种子**<br>
- ### Description
&ensp;伪随机数发生器（PRNG）在每次初始化产品时使用相同的种子。
- ### Extended Description
&ensp;如果攻击者可以猜测（或知道）种子，则攻击者可能能够确定将从PRNG生成的随机数。<br>

## <font color=gray>**CWE - 337	Predictable Seed in Pseudo-Random Number Generator (PRNG)**</font><br>
中文：**伪随机数发生器（PRNG）中的可预测种子**<br>
- ### Description
&ensp;伪随机数发生器（PRNG）从可预测的种子初始化，例如进程ID或系统时间。
- ### Extended Description
&ensp;可预测种子的使用显着减少了攻击者需要测试的可能种子的数量，以便预测PRNG将生成哪些随机numnbers。<br>

## <font color=gray>**CWE - 338	Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)**</font><br>
中文：**使用密码弱伪随机数发生器（PRNG）**<br>
- ### Description
&ensp;该产品在安全上下文中使用伪随机数生成器（PRNG），但PRNG的算法在加密方面不强。
- ### Extended Description
&ensp;当在加密上下文中使用非加密PRNG时，它可以将加密暴露给某些类型的攻击。
通常，伪随机数发生器（PRNG）不是为加密而设计的。对于使用随机数的算法，有时候平庸的随机性来源是充分的或者更可取的。弱发电机通常需要较少的处理能力和/或不在系统上使用宝贵的有限熵源。虽然这些PRNG可能具有非常有用的功能，但这些相同的功能可用于打破加密。<br>

## <font color=gray>**CWE - 339	Small Seed Space in PRNG**</font><br>
中文：**PRNG的小种子空间**<br>
- ### Description
&ensp;PRNG使用相对较小的种子空间。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 340	Predictability Problems**</font><br>
中文：**可预测性问题**<br>
- ### Description
&ensp;此类别中的弱点与生成数字或标识符的方案相关，这些数字或标识符比应用程序所需的更可预测。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 341	Predictable from Observable State**</font><br>
中文：**从可观察国家可预测**<br>
- ### Description
&ensp;根据攻击者可以对系统或网络的状态（例如时间，进程ID等）进行的观察，可以预测数字或对象。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 342	Predictable Exact Value from Previous Values**</font><br>
中文：**先前值的可预测精确值**<br>
- ### Description
&ensp;通过观察先前的值可以精确地预测精确值或随机数。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 343	Predictable Value Range from Previous Values**</font><br>
中文：**先前值的可预测值范围**<br>
- ### Description
&ensp;该软件的随机数发生器产生一系列值，当观察到这些值时，可用于推断可能产生的下一个值的相对小范围的可能性。
- ### Extended Description
&ensp;根据对先前值的观察，不应预测随机数发生器的输出。在某些情况下，攻击者无法预测接下来会产生的确切值，但可以显着缩小可能性。这减少了执行暴力攻击的努力量。例如，假设产品生成1到100之间的随机数，但它总是产生一个更大的值，直到达到100.如果生成器产生80，那么攻击者知道下一个值将介于81和100之间。在100种可能性中，攻击者只需要考虑20种。<br>

## <font color=gray>**CWE - 344	Use of Invariant Value in Dynamically Changing Context**</font><br>
中文：**在动态变化的上下文中使用不变值**<br>
- ### Description
&ensp;该产品使用常量值，名称或引用，但此值可以（或应该）在不同的环境中变化。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 345	Insufficient Verification of Data Authenticity**</font><br>
中文：**数据真实性验证不足**<br>
- ### Description
&ensp;该软件无法充分验证数据的来源或真实性，导致其接受无效数据。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 346	Origin Validation Error**</font><br>
中文：**原点验证错误**<br>
- ### Description
&ensp;该软件未正确验证数据源或通信是否有效。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 347	Improper Verification of Cryptographic Signature**</font><br>
中文：**密码签名的不正确验证**<br>
- ### Description
&ensp;该软件不会验证或错误地验证数据的加密签名。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 348	Use of Less Trusted Source**</font><br>
中文：**使用较少可信源**<br>
- ### Description
&ensp;该软件具有相同数据或信息的两个不同来源，但它使用的源代码对验证的支持较少，信任度较低，或者抵御攻击的能力较弱。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 349	Acceptance of Extraneous Untrusted Data With Trusted Data**</font><br>
中文：**使用可信数据接受外部不受信任的数据**<br>
- ### Description
&ensp;该软件在处理可信数据时，接受可信数据中包含的任何不受信任的数据，将不受信任的数据视为可信数据。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 350	Reliance on Reverse DNS Resolution for a Security-Critical Action**</font><br>
中文：**依赖反向DNS解决方案来实现安全关键行动**<br>
- ### Description
&ensp;该软件对IP地址执行反向DNS解析以获取主机名并做出安全决策，但它无法正确确保IP地址与主机名真正关联。
- ### Extended Description
&ensp;由于DNS名称很容易被欺骗或误报，并且软件可能难以检测可信DNS服务器是否已被泄露，因此DNS名称不构成有效的认证机制。
当软件对IP地址执行反向DNS解析时，如果攻击者控制服务器获取该IP地址，则攻击者可以使服务器返回任意主机名。因此，攻击者可能绕过身份验证，导致错误的主机名记录在日志文件中以隐藏活动或执行其他攻击。
攻击者可以通过（1）破坏DNS服务器并修改其记录（有时称为DNS缓存中毒）或（2）对与其IP地址关联的DNS服务器进行合法控制来欺骗DNS名称。<br>

## <font color=gray>**CWE - 351	Insufficient Type Distinction**</font><br>
中文：**类型区别不足**<br>
- ### Description
&ensp;该软件无法以导致不安全行为的方式正确区分不同类型的元素。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 352	Cross-Site Request Forgery (CSRF)**</font><br>
中文：**跨站请求伪造（CSRF）**<br>
- ### Description
&ensp;Web应用程序没有或不能充分验证提交请求的用户是否有意提供了格式良好，有效，一致的请求。
- ### Extended Description
&ensp;当Web服务器被设计为从客户端接收请求而没有任何机制来验证它是否被故意发送时，攻击者可能会欺骗客户端向Web服务器发出无意的请求，该请求将被视为真实的要求。这可以通过URL，图像加载，XMLHttpRequest等来完成，并且可能导致数据暴露或意外的代码执行。<br>

## <font color=gray>**CWE - 353	Missing Support for Integrity Check**</font><br>
中文：**缺少对完整性检查的支持**<br>
- ### Description
&ensp;该软件使用传输协议，该协议不包括用于在传输期间验证数据完整性的机制，例如校验和。
- ### Extended Description
&ensp;如果从协议中省略完整性检查值或“校验和”，则无法确定数据在传输中是否已损坏。协议中缺少校验和功能会删除可以使用的数据的第一个应用程序级别检查。端到端的检查理念指出，完整性检查应该在可以完全实现的最低级别执行。除了应用程序执行的进一步的健全性检查和输入验证之外，协议的校验和是最重要的校验和级别，因为它可以比任何先前级别更完整地执行并且考虑整个消息，而不是单个数据包。<br>

## <font color=gray>**CWE - 354	Improper Validation of Integrity Check Value**</font><br>
中文：**对完整性检查值的不正确验证**<br>
- ### Description
&ensp;该软件不验证或错误地验证消息的完整性检查值或“校验和”。这可以防止它检测数据是否在传输中被修改或损坏。
- ### Extended Description
&ensp;使用前对校验和的不正确验证会导致不必要的风险，可以轻松减轻。协议规范描述了用于计算校验和的算法。然后，实现计算并验证计算的校验和与接收的校验和匹配是一件简单的事情。对计算的校验和和接收的校验和的不正确验证可能导致更大的后果。<br>

## <font color=gray>**CWE - 356	Product UI does not Warn User of Unsafe Actions**</font><br>
中文：**产品UI不会警告不安全操作的用户**<br>
- ### Description
&ensp;在代表该用户执行不安全操作之前，该软件的用户界面不会警告用户。这使攻击者更容易诱骗用户对其系统造成损害。
- ### Extended Description
&ensp;软件系统应警告用户，如果用户继续进行，可能会发生潜在危险的操作。例如，如果用户从未知来源下载文件并尝试在其计算机上执行该文件，则应用程序的GUI可以指示该文件不安全。<br>

## <font color=gray>**CWE - 357	Insufficient UI Warning of Dangerous Operations**</font><br>
中文：**危险操作的UI警告不足**<br>
- ### Description
&ensp;用户界面向用户提供有关危险或敏感操作的警告，但警告不足以引起注意。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 358	Improperly Implemented Security Check for Standard**</font><br>
中文：**未正确实施标准安全检查**<br>
- ### Description
&ensp;该软件未实现或错误地实现由标准化算法，协议或技术的设计指定的一个或多个安全相关检查。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 359	Exposure of Private Information ('Privacy Violation')**</font><br>
中文：**私人信息的曝光（'隐私违规'）**<br>
- ### Description
&ensp;该软件无法正确防止私人数据（如信用卡号）被（1）未明确授权访问数据或（2）未获得数据所针对的人的默许相关的。
- ### Extended Description
&ensp;错误处理私人信息（例如客户密码或社会安全号码）可能会损害用户隐私，而且通常是非法的。私人信息的曝光并不一定会妨碍软件正常工作，事实上它可能是开发人员想要的，但对于与此私人信息相关的人来说，它仍然是不受欢迎的（或法律明确禁止）。
在以下情况下可能发生隐私


私人用户信息进入该程序。
数据将写入外部位置，例如控制台，文件系统或网络。


私人数据可以通过多种方式进入程序：


直接来自用户的密码或个人信息的形式
应用程序从数据库或其他数据存储访问
间接来自合作伙伴或其他第三方


某些类型的私人信息包括：


政府标识符，例如社会安全号码
联系信息，如家庭住址和电话号码
地理位置 - 用户所在的位置
工作经历
财务数据 - 例如信用卡号，工资，银行账户和债务
图片，视频或音频
行为模式 - 例如网上冲浪历史，执行某些活动时等。
与他人的关系（和关系类型） - 家人，朋友，联系人等。
通讯 - 电子邮件地址，私人电子邮件，短信，聊天记录等。
健康 - 医疗条件，保险状况，处方记录
凭证，例如密码，可用于访问其他信息。


这些信息中的一些可以被表征为PII（个人可识别信息），受保护的健康信息（PHI）等。私人信息的类别可以基于特定行业的预期用途或政策和实践而重叠或变化。
根据其所在地，所经营的业务类型以及其处理的任何私人数据的性质，组织可能需要遵守以下一项或多项联邦和州法规： - 安全港隐私框架[REF-340 ]  -  Gramm-Leach Bliley Act（GLBA）[REF-341]  - 健康保险流通与责任法案（HIPAA）[REF-342]  - 加州SB-1386 [REF-343]。
有时，未标记为私有的数据可能在不同的上下文中具有隐私含义。例如，学生识别号码通常不被视为私人，因为没有明确且公开可用的映射到个别学生的个人信息。但是，如果学校根据学生的社会安全号码生成识别号码，则识别号码应视为私密号码。
安全和隐私问题似乎经常相互竞争。从安全角度来看，应记录所有重要操作，以便以后可以识别任何异常活动。但是，当涉及私人数据时，这种做法实际上可能会产生风险。尽管有许多方法可以不安全地处理私人数据，但共同的风险源于错误的信任。程序员通常信任程序运行的操作环境，因此认为可以接受在文件系统，注册表或其他本地控制的资源中存储私有信息。但是，即使限制对某些资源的访问，也不能保证可以信任具有访问权限的个人。<br>

## <font color=gray>**CWE - 360	Trust of System Event Data**</font><br>
中文：**信任系统事件数据**<br>
- ### Description
&ensp;基于事件位置的安全性是不安全的，可能是欺骗性的。
- ### Extended Description
&ensp;事件是消息传递系统，其可以向监听事件的程序提供控制数据。事件通常没有任何类型的身份验证框架，以允许从受信任的来源验证它们。 Windows中的任何应用程序都可以在给定桌面上向同一桌面上的任何窗口发送消息。这些消息没有身份验证框架。因此，如果进程未检查这些消息的有效性和安全性，则可以使用任何消息来操作桌面上的任何进程。<br>

## <font color=gray>**CWE - 362	Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')**</font><br>
中文：**使用具有不正确同步的共享资源并发执行（'竞争条件'）**<br>
- ### Description
&ensp;该程序包含可与其他代码并发运行的代码序列，并且代码序列需要对共享资源的临时，独占访问，但存在时序窗口，其中共享资源可由另一个并发操作的代码序列修改。
- ### Extended Description
&ensp;当预期的同步在安全关键代码中时，这可能具有安全隐患，例如记录用户是否经过身份验证或修改不应受到局外人影响的重要状态信息。
竞争条件发生在并发环境中，并且实际上是代码序列的属性。根据上下文，代码序列可以是函数调用，少量指令，一系列程序调用等形式。
竞争条件违反了这些与之密切相关的属性：


排他性 - 给予代码序列对共享资源的独占访问权，即，在原始序列完成执行之前，没有其他代码序列可以修改共享资源的属性。
原子性 - 代码序列是行为原子的，即，没有其他线程或进程可以同时针对相同资源执行相同的指令序列（或子集）。


当“干扰代码序列”仍然可以访问共享资源时，存在竞争条件，违反了排他性。程序员可以假设某些代码序列执行得太快而不受干扰代码序列的影响;如果不是，那就违反了原子性。例如，单个“x ++”语句在代码层可能看起来是原子的，但它在指令层实际上是非原子的，因为它涉及读取（x的原始值），然后是计算（x + 1） ），然后写入（将结果保存到x）。
干扰代码序列可以是“可信任的”或“不可信的”。可信的干扰码序列发生在程序内;它不能被攻击者修改，只能间接调用。不受信任的干扰代码序列可以由攻击者直接创作，通常它位于易受攻击的程序外部。<br>

## <font color=gray>**CWE - 363	Race Condition Enabling Link Following**</font><br>
中文：**竞争条件启用链接跟随**<br>
- ### Description
&ensp;软件在访问之前检查文件或目录的状态，这会产生竞争条件，在执行访问之前可以用链接替换文件，从而导致软件访问错误的文件。
- ### Extended Description
&ensp;虽然开发人员可能期望在检查时间和使用时间之间存在非常窄的时间窗口，但仍存在竞争条件。攻击者可能导致软件速度变慢（例如，内存消耗），导致时间窗口变大。或者，在某些情况下，攻击者可以通过执行大量攻击来赢得比赛。<br>

## <font color=gray>**CWE - 364	Signal Handler Race Condition**</font><br>
中文：**信号处理器竞争条件**<br>
- ### Description
&ensp;该软件使用引入竞争条件的信号处理程序。
- ### Extended Description
&ensp;竞争条件经常发生在信号处理程序中，因为信号处理程序支持异步动作。这些种族条件有各种根本原因和症状。攻击者可能能够利用信号处理程序竞争条件导致软件状态被破坏，可能导致拒绝服务甚至代码执行。
当信号处理程序中发生非重入函数或状态敏感操作时，会发生这些问题，可以随时调用它们。这些行为可能违反被中断的“常规”代码或可能被调用的其他信号处理程序所做出的假设。如果在不合适的时刻调用这些函数 - 例如在非重入函数已经运行时 - 可能会发生内存损坏，这可能会被代码执行利用。通常发现的另一种信号竞争条件发生在信号处理程序中调用free时，导致双重释放，从而导致write-what-where条件。即使给定指针在释放后设置为NULL，在释放内存和指针设置为NULL之间仍然存在争用条件。如果为多个信号设置了相同的信号处理程序，则这尤其成问题 - 因为这意味着可以重新输入信号处理程序本身。
有几个与信号处理程序相关的已知行为已经收到“信号处理程序竞争条件”的标签：


信号处理程序和“常规”代码都可访问的共享状态（例如全局数据或静态变量）
信号处理程序和其他信号处理程序之间的共享状态
在信号处理程序中使用非重入功能 - 这通常意味着正在使用共享状态。例如，malloc（）和free（）是不可重入的，因为它们可能使用全局或静态数据结构来管理内存，并且它们被无辜的看似函数间接使用，例如syslog（）;这些函数可能被用于内存损坏，可能还有代码执行。
将相同的信号处理函数与多个信号相关联 - 这可能意味着共享状态，因为访问了相同的代码和资源。例如，这可能是双重免费和使用后免费弱点的来源。
使用setjmp和longjmp，或阻止信号处理程序将控制权返回到原始功能的其他机制
虽然从技术上讲不是竞争条件，但是一些信号处理程序被设计为最多被调用一次，并且被调用不止一次会引入安全问题，即使没有任何并发​​调用信号处理程序。这可能是双重免费和使用后免费弱点的来源。


信号处理程序漏洞通常基于缺少特定保护机制进行分类，尽管CWE不鼓励这种分类，因为程序员通常可以选择几种不同的机制来解决这些弱点。这种保护机制可以保留对共享资源的访问权限，以及相关代码的行为原子性：


避免共享状态
在信号处理程序中使用同步
在常规代码中使用同步
禁用或屏蔽其他信号，提供原子性（有效确保排他性）<br>

## <font color=gray>**CWE - 365	Race Condition in Switch**</font><br>
中文：**交换机中的竞争条件**<br>
- ### Description
&ensp;该代码包含一个switch语句，其中可以在交换机仍在执行时修改切换变量，从而导致意外行为。
- ### Extended Description
&ensp;这个问题在涉及直通式案例陈述的switch语句中尤为重要 - 即那些不以break结尾的语句。如果交换机测试的变量在执行过程中发生变化，这可能会改变交换机的预期逻辑，以至于它将进程置于矛盾状态，在某些情况下甚至可能导致内存损坏。<br>

## <font color=gray>**CWE - 366	Race Condition within a Thread**</font><br>
中文：**线程中的竞争条件**<br>
- ### Description
&ensp;如果两个执行线程同时使用资源，则存在可能在无效时使用资源的可能性，从而使得执行状态未定义。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 367	Time-of-check Time-of-use (TOCTOU) Race Condition**</font><br>
中文：**检查时间（TOCTOU）竞赛条件**<br>
- ### Description
&ensp;软件在使用该资源之前检查资源的状态，但资源的状态可以在检查和使用之间以一种使检查结果无效的方式发生变化。这可能导致软件在资源处于意外状态时执行无效操作。
- ### Extended Description
&ensp;当攻击者可以在检查和使用之间影响资源状态时，这种弱点可能与安全相关。这可能发生在共享资源（如文件，内存，甚至是多线程程序中的变量）中。<br>

## <font color=gray>**CWE - 368	Context Switching Race Condition**</font><br>
中文：**上下文切换竞争条件**<br>
- ### Description
&ensp;产品执行一系列非原子操作以在跨越特权或其他安全边界的上下文之间切换，但竞争条件允许攻击者在切换期间修改或歪曲产品的行为。
- ### Extended Description
&ensp;这通常出现在Web浏览器漏洞中，攻击者可以在浏览器从受信任域转换到不受信任域时执行某些操作，反之亦然，浏览器使用信任级别和资源在一个域上执行操作。其他域名。<br>

## <font color=gray>**CWE - 369	Divide By Zero**</font><br>
中文：**除以零**<br>
- ### Description
&ensp;产品将值除以零。
- ### Extended Description
&ensp;当向产品提供意外值时，或者如果发生未正确检测到的错误，通常会发生此弱点。它经常发生在涉及物理尺寸的计算中，例如尺寸，长度，宽度和高度。<br>

## <font color=gray>**CWE - 370	Missing Check for Certificate Revocation after Initial Check**</font><br>
中文：**初始检查后缺少检查证书撤销**<br>
- ### Description
&ensp;软件在初始撤销检查后不检查证书的撤销状态，这可能导致软件即使在稍后撤销证书后也执行特权操作。
- ### Extended Description
&ensp;如果在每个需要权限的操作之前未检查证书的撤销状态，则系统可能会受到竞争条件的影响。如果在初始检查后撤销证书，则与撤销证书的所有者一起执行的所有后续操作都将失去证书保证的所有权益。实际上，几乎可以肯定使用撤销证书表示恶意活动。<br>

## <font color=gray>**CWE - 372	Incomplete Internal State Distinction**</font><br>
中文：**不完整的内部状态区别**<br>
- ### Description
&ensp;软件没有正确地确定它所处的状态，导致它假设它处于状态X，而实际上它处于状态Y，导致它以安全相关的方式执行不正确的操作。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 373	DEPRECATED: State Synchronization Error**</font><br>
中文：**DEPRECATED：状态同步错误**<br>
- ### Description
&ensp;此条目已弃用，因为它与竞争条件（CWE-362）和不正确同步（CWE-662）相同的概念重叠。
- ### Extended Description
&ensp;没有详细描述<br>

## <font color=gray>**CWE - 374	Passing Mutable Objects to an Untrusted Method**</font><br>
中文：**将可变对象传递给不受信任的方法**<br>
- ### Description
&ensp;程序将非克隆的可变数据作为参数发送给方法或函数。
- ### Extended Description
&ensp;已调用的函数或方法可以更改或删除可变数据。这可能违反了调用函数对其状态所做的假设。在通过引用可变数据调用未知代码的情况下，此外部代码可以对发送的数据进行更改。如果先前未克隆此数据，则修改后的数据在执行上下文中可能无效。<br>

## <font color=gray>**CWE - 375	Returning a Mutable Object to an Untrusted Caller**</font><br>
中文：**将可变对象返回给不受信任的调用者**<br>
- ### Description
&ensp;将非克隆的可变数据作为返回值发送可能导致该数据被调用函数更改或删除。
- ### Extended Description
&ensp;在函数返回对可变数据的引用的情况下，调用该函数的外部代码可能会对发送的数据进行更改。如果此数据先前未被克隆，则该类将使用可能违反其内部状态假设的修改数据。<br>

