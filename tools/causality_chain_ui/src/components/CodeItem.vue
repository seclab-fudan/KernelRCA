<script setup>
import 'highlight.js/styles/github.css';
import { ref, computed, nextTick, onMounted, watch } from 'vue';
import { lineNumbersBlock } from "@/assets/js/highlight-line-number";
import hljs from "highlight.js";
import { progressProps } from 'element-plus';

const props = defineProps({
  id: {
    type: String,
    required: true
  },
  inlineLevel: {
    type: String,
    required: true
  },
  sourceCode: {
    type: Object,
    required: true
  },
  codeBoxHeight: {
    type: Number,
    required: true
  },
  index: {
    type: Number,
    required: true
  }
})
const code = "";
const inline_level = ref(props.inlineLevel);

const codeContainer = ref(null);

onMounted(() => {
  showSourceCode();
})

watch(
  () => props.sourceCode,
  (newValue, oldValue) => {
    if (newValue !== oldValue) {
      showSourceCode();
    }
  },
  { deep: true }
);

const showSourceCode = async () => {
  await nextTick();

  const codeElement = document.getElementById(props.id);

  const codeContent = props.sourceCode.code.join("\n")
  const processedCode = codeContent.replace(/\t/g, '    ');
  const highlightedCode = hljs.highlightAuto(processedCode).value;

  codeElement.innerHTML = highlightedCode;

  lineNumbersBlock(codeElement, { startFrom: props.sourceCode.start });

  const lineElement = codeElement.querySelector(`.hljs-ln-line.hljs-ln-code[data-line-number="${props.sourceCode.highlight}"]`);
  if (lineElement) {
    lineElement.style.backgroundColor = 'var(--active--color)';
  }
  if (codeContainer.value) {
    const scrollPercent = (props.sourceCode.highlight - props.sourceCode.start + 1) / (props.sourceCode.code.length + 3)
      - ((props.codeBoxHeight + 1) / 2) / codeContainer.value.scrollHeight
    codeContainer.value.scrollTop = codeContainer.value.scrollHeight * scrollPercent;
  }
};

</script>

<template>
  <div class="codeBox" :style="{ height: props.codeBoxHeight + 'vh' }">
    <div class="codeHeader">
      <el-row>
        <el-tag type="primary" size="small">{{ inline_level }}</el-tag>
        <el-link type="primary" :href="props.sourceCode.url" style="margin-left: 5px;font-size: 12px">{{
          props.sourceCode.file }}</el-link>
      </el-row>
    </div>
    <div class="codeContentBox" ref="codeContainer">
      <pre>
        <code :id="props.id">{{ code }}</code>
      </pre>
    </div>
  </div>
</template>

<style>
.codeBox {
  border-bottom: 2px solid darkcyan;
  position: relative;
  width: 100%;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.codeHeader {
  position: sticky;
  top: 0;
  background-color: #fafafa;
  z-index: 2;
  padding: 5px;
  border-bottom: 1px solid #ccc;
}

.codeContentBox {
  flex: 1;
  overflow-y: auto;
  padding-left: 2px;
  position: relative;
}

pre {
  margin: 0 !important;
}

table.hljs-ln {
  border-spacing: 0 !important;
}
</style>
